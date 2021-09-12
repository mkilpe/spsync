#include "client_sync.hpp"
#include "record_util.hpp"

#include <spsync/core/crypto_context.hpp>
#include <spsync/core/progress.hpp>
#include <spsync/engine/sync_engine.hpp>
#include <spsync/engine/record_verifier.hpp>
#include <spsync/comm/net_connection.hpp>

#include <securepath/common/key_value_database.hpp>
#include <securepath/util/error.hpp>

namespace securepath::sync {

namespace {
	struct dummy_progress : sync::progress {
		dummy_progress(event_system::event_loop& eloop) : progress(eloop) {}
		void handle_event(std::unique_ptr<event_system::event_base>) override {}
	};
}

struct client_sync::impl : engine_output {

	impl(client_sync* parent, event_system::event_loop& loop, database::connection_ptr db)
	: engine_output(loop)
	, parent(parent)
	, db(db)
	, progress(loop)
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

	void init(storage_id const& sid, network_connection& conn) {
		storage = std::make_unique<record_storage>(db);
		enc_keys = std::make_unique<encryption_key_storage>(db);
		crypto = std::make_unique<sync::crypto_context>(conn.context().public_keys(), conn.context().private_data(), *enc_keys);

		storage_connection sconn{conn.create_storage_connection(sid, *storage, progress)};
		engine = std::make_unique<sync_engine>(event_loop(), sconn.input(), *crypto, sync_engine_config{});
		engine->set_output(this);

		//after this the events will be received
		sconn.attach(*engine);
	}

	record_handle create_initial_record(users us, metadata mdata) {
		assert(engine);
		assert(enc_keys);
		enc_keys->create_key();
		return engine->sync_user_change(encrypt_last_key_for_users(us, *crypto), std::move(mdata));
	}


	void on_object_data_changed(record_handle rec) override {
		assert(engine);

		auto record = rec->record();
		auto obj_rec = record.deserialise_to<sync::data_change_record>();

		auto key = enc_keys->find(obj_rec.encryption_key());
		if(key) {
			sync::data_change_record_verifier ver(*key, obj_rec, record.auth());
			if(ver.is_authentic()) {
				std::deque<single_data_change> res;
				for(auto const& h : ver.headers()) {
					res.push_back(single_data_change{h.data, h.header});
				}
				if(!res.empty()) {
					parent->on_data_change(rec, std::move(res));
				}
			} else {
				LOG_WARN("message not authentic");
			}
		} else {
			LOG_WARN("could not find key to decrypt message (seq=%)", obj_rec.encryption_key());
		}
	}

	void process_user_change(plain_user_change_data const& change) {
		auto us = change.access();
		database::transaction trans{*db};

		if(us.mode() == users_change_mode::full) {
			remove_all_members();
			for(auto const& v : change.access()) {
				create_member(v.user, member_status::member);
			}
		} else {
			for(auto const& v : change.access()) {
				member_status status;
				auto k = find_member(v.user, status);
				if(k && v.access == util::access_type::no_access) {
					remove_member(v.user);
				} else if(!k) {
					create_member(v.user, member_status::member);
				} else {
					set_member_status(v.user, member_status::member);
				}
			}
		}
	}

	void on_user_changed(record_handle rec) override {
		assert(engine);

		auto record = rec->record();
		auto user_rec = record.deserialise_to<sync::user_change_record>();

		auto key = enc_keys->find(user_rec.encryption_key());
		if(key) {
			sync::user_change_record_verifier ver(*key, user_rec, record.auth());
			if(ver.is_authentic()) {
				process_user_change(ver.data());
				parent->on_user_change(rec, user_change{ver.data().access(), ver.header().metadata()});
			} else {
				LOG_WARN("message not authentic");
			}
		} else {
			LOG_WARN("could not find key to decrypt message (seq=%)", user_rec.encryption_key());
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
		q.bind(":status", static_cast<std::int64_t>(status));
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
		q.bind(":status", static_cast<std::int64_t>(status));
		q.execute();
	}

	void add_or_remove_user_access(users const& us) {
		if(us.mode() != users_change_mode::delta) {
			LOG_WARN("users change is not in delta mode: %", us);
			throw make_error(securepath::errc::invalid_data, "users change is not in delta mode");
		}
		engine->sync_user_change(encrypt_last_key_for_users(us, *crypto), metadata{});
	}

public:
	client_sync* parent;
	database::connection_ptr db;

	dummy_progress progress;

	std::unique_ptr<record_storage> storage;
	std::unique_ptr<encryption_key_storage> enc_keys;
	std::unique_ptr<sync::crypto_context> crypto;

	std::unique_ptr<sync_engine> engine;
};

client_sync::client_sync(event_system::event_loop& loop, database::connection_ptr db)
: impl_(std::make_unique<impl>(this, loop, db))
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
	assert(impl_->engine);
	return impl_->engine->sync_object_change(std::move(oid), std::move(mdata), dhandle);
}

record_handle client_sync::send_user_change(users us, metadata mdata) {
	assert(impl_->engine);
	if(!impl_->storage->last_block().is_valid()) {
		return impl_->create_initial_record(std::move(us), std::move(mdata));
	} else {
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
	impl_->create_member(uid, member_status::pending_add);
	return find_member(uid);
}

void client_sync::remove_member(util::user_id const& uid) {
	users us{users_change_mode::delta};
	us.remove(uid);
	impl_->add_or_remove_user_access(us);
	impl_->set_member_status(uid, member_status::pending_remove);
}

void client_sync::apply(users const& us) {
	if(us.mode() == users_change_mode::full) {
		LOG_WARN("apply full mode change not implemented");
		throw make_error(securepath::errc::not_implemented, "apply full mode change not implemented");
	} else {
		impl_->add_or_remove_user_access(us);
		for(auto v : us.access()) {
			member_status status;
			if(impl_->find_member(v.user, status)) {
				if(v.access == util::access_type::no_access) {
					impl_->set_member_status(v.user, member_status::pending_remove);
				} else if(status == member_status::pending_remove) {
					impl_->set_member_status(v.user, member_status::pending_add);
				}
			} else if(v.access != util::access_type::no_access) {
				impl_->set_member_status(v.user, member_status::pending_add);
			}
		}
	}
}

sync::crypto_context& client_sync::crypto_context() const {
	assert(impl_->crypto);
	return *impl_->crypto;
}

}