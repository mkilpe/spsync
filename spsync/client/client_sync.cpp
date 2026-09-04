#include "client_sync.hpp"

#include <utility>
#include <securepath/crypto/public_key_access.hpp>
#include "record_util.hpp"

#include <spsync/core/crypto_context.hpp>
#include <spsync/core/progress.hpp>
#include <spsync/core/user_merge.hpp>
#include <spsync/core/records/segment_record.hpp>
#include <spsync/engine/sync_engine.hpp>
#include <spsync/engine/record_verifier.hpp>
#include <spsync/comm/net_connection.hpp>

#include <securepath/common/key_value_database.hpp>
#include <securepath/util/error.hpp>

namespace securepath::sync {

namespace {
	struct dummy_progress : sync::progress {
		dummy_progress(event_system::event_loop& eloop) : progress(eloop) {}
		~dummy_progress() { stop_handler(); }
		void handle_event(std::unique_ptr<event_system::event_base>) override {}
	};
}

struct client_sync::impl : engine_output {

	impl(client_sync* parent, network::context& cc, event_system::event_loop& loop, database::connection_ptr db, sync_engine_config config)
	: engine_output(loop)
	, parent(parent)
	, db(db)
	, progress(loop)
	, storage(db)
	, enc_keys(db)
	, crypto(cc.public_keys(), cc.private_data(), enc_keys, storage)
	, config(std::move(config))
	{
		if(!db->has_table("members")) {
			std::string prepare_str =
				"CREATE TABLE members("
					"key INTEGER PRIMARY KEY,"
					"key_id TEXT UNIQUE,"
					"status INTEGER);";
			db->prepare(prepare_str).execute();
		}
	}

	~impl() {
		stop_handler();
	}

	void init(storage_id const& sid, network_connection& conn) {
		storage_connection sconn{conn.create_storage_connection(sid, storage, progress, storage_modes{config.mode, config.auth_mode, config.replication})};
		engine = std::make_unique<sync_engine>(event_loop(), sconn.input(), crypto, config);
		engine->set_output(this);

		//after this the events will be received
		sconn.attach(*engine);
	}

	record_handle create_initial_record(users us, metadata mdata) {
		assert(engine);
		enc_keys.create_key();
		update_members(us);
		return engine->sync_user_change(encrypt_last_key_for_users(us, crypto), std::move(mdata));
	}


	void on_object_data_changed(record_handle rec) override {
		assert(engine);

		std::deque<single_data_change> res;
		error err = extract_single_data_changes(enc_keys, rec, res);

		//t: how to handle errors here?

		if(!err && !res.empty()) {
			parent->on_data_change(rec, std::move(res));
		}
	}

	/// the stored key of the record's sequence that authenticates the user change;
	/// colliding key rotations keep several keys per sequence (D9), each is tried
	std::optional<encryption_key> find_user_change_key(sync::user_change_record const& rec, chain_block const& block) const {
		std::optional<encryption_key> ret;
		for(auto const& key : enc_keys.find_all(rec.encryption_key())) {
			if(!ret) {
				try {
					sync::user_change_record_verifier ver(key, rec, block.auth());
					if(ver.is_authentic()) {
						ret = key;
					}
				} catch(std::exception const&) {
					// a wrong candidate decrypts garbage that fails to parse
				}
			}
		}
		return ret;
	}

	/**
	 * Rebuild the membership from every in sync user change with the D9 merge fold
	 * (plan 4.6). The fold is deterministic on the record set, so every replica derives
	 * the same members even when the local orders differ; the local pending user
	 * changes are re-applied on top as pending states.
	 */
	void recompute_members() {
		std::vector<user_change_entry> entries;
		std::map<record_tag, record_tag> parent_special;

		for(auto const& h : storage.find_all_of_type(segment_record_tag)) {
			auto block = h->record();
			parent_special[block.tag()] = block.deserialise_to<segment_record>().last_seen_special_tag();
		}
		for(auto const& h : storage.find_all_of_type(user_change_record_tag)) {
			auto block = h->record();
			auto rec = block.deserialise_to<sync::user_change_record>();
			parent_special[block.tag()] = rec.last_seen_special_tag();
			if(auto key = find_user_change_key(rec, block)) {
				sync::user_change_record_verifier ver(*key, rec, block.auth());
				entries.push_back(user_change_entry{ver.data().access(), block.tag(), rec.last_seen_special_tag()});
			} else {
				LOG_WARN("skipping user change without a verifying key [tag={}]", to_hex(block.tag()));
			}
		}
		auto const merged = merge_user_changes(entries, parent_special);
		LOG_TRACE("recomputed members [changes={}, members={}]", entries.size(), merged.size());

		database::transaction trans{*db};
		remove_all_members();
		for(auto const& ua : merged) {
			create_member(ua.user, member_status::member);
		}
		for(auto h = storage.find_first_pending_commit(); h; h = storage.find_next_pending_commit(h)) {
			if(h->type() == user_change_record_tag) {
				auto block = h->record();
				auto rec = block.deserialise_to<sync::user_change_record>();
				if(auto key = find_user_change_key(rec, block)) {
					sync::user_change_record_verifier ver(*key, rec, block.auth());
					update_members(ver.data().access());
				}
			}
		}
	}

	void on_user_changed(record_handle rec) override {
		assert(engine);

		auto record = rec->record();
		auto user_rec = record.deserialise_to<sync::user_change_record>();

		auto key = find_user_change_key(user_rec, record);
		if(key) {
			sync::user_change_record_verifier ver(*key, user_rec, record.auth());
			// the membership is re-derived with the D9 fold: a foreign user change can
			// arrive anywhere in the local order (plan 4.6)
			recompute_members();
			parent->on_user_change(rec,
				user_change{
					ver.data().access(),
					ver.header().metadata(),
					record.auth().signature_issuer()});
		} else {
			LOG_WARN("could not verify user change (seq={})", user_rec.encryption_key());
		}
	}

	std::optional<std::uint64_t> find_member(util::user_id const& uid, member_status& status) const {
		auto q = db->prepare("SELECT key, status FROM members WHERE key_id = :id");
		q.bind(":id", uid.public_key_id().data());

		auto res = q.execute();

		std::optional<std::uint64_t> ret;
		if(res) {
			ret = res.value<std::uint64_t>(0);
			status = static_cast<member_status>(res.value<std::int64_t>(1).value_or(0));
		}
		return ret;
	}

	void create_member(util::user_id const& uid, member_status status) {
		if(!uid.is_valid()) {
			throw make_error(securepath::errc::invalid_data, "invalid user id");
		}
		auto q = db->prepare("INSERT INTO members(key_id, status) VALUES(:id, :status);");
		q.bind(":id", uid.public_key_id().data());
		q.bind(":status", std::to_underlying(status));
		q.execute();
	}

	void remove_member(util::user_id const& uid) {
		auto q = db->prepare("DELETE FROM members WHERE key_id = :id");
		q.bind(":id", uid.public_key_id().data());
		q.execute();
	}

	void remove_all_members() {
		auto q = db->prepare("DELETE FROM members");
		q.execute();
	}

	void set_member_status(util::user_id const& uid, member_status status) {
		auto q = db->prepare("UPDATE members SET status = :status WHERE key_id = :id;");
		q.bind(":id", uid.public_key_id().data());
		q.bind(":status", std::to_underlying(status));
		q.execute();
	}

	void update_members(users const& us) {
		if(us.mode() == users_change_mode::delta) {
			for(auto v : us.access()) {
				member_status status;
				if(find_member(v.user, status)) {
					if(v.access == util::access_type::no_access) {
						set_member_status(v.user, member_status::pending_remove);
					} else if(status == member_status::pending_remove) {
						set_member_status(v.user, member_status::pending_add);
					}
				} else if(v.access != util::access_type::no_access) {
					create_member(v.user, member_status::pending_add);
				}
			}
		} else {
			remove_all_members();
			for(auto const& v : us.access()) {
				create_member(v.user, member_status::pending_add);
			}
		}
	}

	void add_or_remove_user_access(users const& us) {
		assert(engine);
		if(us.mode() != users_change_mode::delta) {
			LOG_WARN("users change is not in delta mode: {}", us);
			throw make_error(securepath::errc::invalid_data, "users change is not in delta mode");
		}
		update_members(us);
		engine->sync_user_change(encrypt_last_key_for_users(us, crypto), metadata{});
	}

public:
	client_sync* parent;
	database::connection_ptr db;

	dummy_progress progress;

	record_storage storage;
	encryption_key_storage enc_keys;
	sync::crypto_context crypto;

	std::unique_ptr<sync_engine> engine;

	sync_engine_config config;
};

client_sync::client_sync(network::context& context, event_system::event_loop& loop, database::connection_ptr db, sync_engine_config config)
: impl_(std::make_unique<impl>(this, context, loop, db, std::move(config)))
{
	add_backend(std::make_shared<key_value_database>(db, "storage_metadata", 0));
}

client_sync::~client_sync()
{
}

void client_sync::init(storage_id const& sid, network_connection& conn) {
	impl_->init(sid, conn);
}

void client_sync::stop_handler() {
	impl_->stop_handler();
}

record_handle client_sync::send_data_change(object_id oid, metadata mdata, record_data_handle dhandle) {
	if(!impl_->engine) {
		throw make_error(securepath::errc::invalid_state, "client sync engine not initialised yet");
	}
	return impl_->engine->sync_object_change(std::move(oid), std::move(mdata), dhandle);
}

record_handle client_sync::send_user_change(users us, metadata mdata) {
	if(!impl_->engine) {
		throw make_error(securepath::errc::invalid_state, "client sync engine not initialised yet");
	}
	if(!impl_->storage.last_block().is_valid()) {
		return impl_->create_initial_record(std::move(us), std::move(mdata));
	} else {
		impl_->update_members(us);
		return impl_->engine->sync_user_change(std::move(us), std::move(mdata));
	}
}

std::deque<std::unique_ptr<member>> client_sync::members() const {
	std::deque<std::unique_ptr<member>>	ret;
	auto q = impl_->db->prepare("SELECT key, status, key_id FROM members;");
	auto res = q.execute();
	for(; res; res.next()) {
		std::optional<std::uint64_t> key = res.value<std::uint64_t>(0);
		if(key) {
			auto status = static_cast<member_status>(res.value<std::int64_t>(1).value_or(0));
			util::user_id uid{crypto::public_key_id{*res.value<octet_vector>(2)}};
			auto p = std::make_unique<member>(uid, status);
			p->add_backend(std::make_shared<key_value_database>(impl_->db, "members_metadata", *key));
			ret.push_back(std::move(p));
		}
	}
	return ret;
}

std::unique_ptr<member> client_sync::find_member(util::user_id const& uid) const {
	std::unique_ptr<member> ret;
	member_status status;
	std::optional<std::uint64_t> member_id = impl_->find_member(uid, status);
	if(member_id) {
		ret = std::make_unique<member>(uid, status);
		ret->add_backend(std::make_shared<key_value_database>(impl_->db, "members_metadata", *member_id));
	}
	return ret;
}

std::unique_ptr<member> client_sync::add_member(util::user_id const& uid) {
	users us{users_change_mode::delta};
	us.add(util::user_access{uid, util::access_type::user_management_access});
	impl_->add_or_remove_user_access(us);
	return find_member(uid);
}

void client_sync::remove_member(util::user_id const& uid) {
	users us{users_change_mode::delta};
	us.remove(uid);
	impl_->add_or_remove_user_access(us);
}

void client_sync::apply(users const& us) {
	impl_->add_or_remove_user_access(us);
}

sync::crypto_context& client_sync::crypto_context() const {
	return impl_->crypto;
}

}