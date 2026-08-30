#include "storage.hpp"

#include <utility>
#include "connection.hpp"

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <spsync/protocol/error.hpp>

#include <securepath/crypto/private_data_access.hpp>

#include <ctime>
#include <filesystem>

namespace securepath::sync {
namespace {

storage_modes load_or_create_modes(database::connection& db, std::optional<storage_modes> const& requested, std::string const& log_id) {
	if(requested && !valid_storage_modes(*requested)) {
		LOG_WARN("replicated storage requires signed records (rsid={})", log_id);
		throw make_error(protocol::errc::invalid_storage_modes, "replicated storage requires sign_records");
	}
	if(!db.has_table("storage_config")) {
		db.prepare("CREATE TABLE storage_config("
			"key INTEGER PRIMARY KEY CHECK(key = 1),"
			"sync_mode INTEGER,"
			"auth_mode INTEGER,"
			"replication INTEGER,"
			"created_at INTEGER);").execute();
	}
	auto q = db.prepare("SELECT sync_mode, auth_mode, replication FROM storage_config WHERE key = 1;");
	auto res = q.execute();
	if(res) {
		storage_modes persisted{
			sync_mode(res.value<std::int64_t>(0).value_or(0)),
			auth_mode(res.value<std::int64_t>(1).value_or(0)),
			replication_mode(res.value<std::int64_t>(2).value_or(0))};
		if(requested && *requested != persisted) {
			LOG_WARN("storage exists with different modes (rsid={})", log_id);
			throw make_error(protocol::errc::storage_mode_mismatch, "storage exists with different modes");
		}
		return persisted;
	}
	storage_modes m = requested.value_or(storage_modes{});
	auto ins = db.prepare("INSERT INTO storage_config(key, sync_mode, auth_mode, replication, created_at) VALUES(1, :m, :a, :r, :c);");
	ins.bind(":m", std::to_underlying(m.mode));
	ins.bind(":a", std::to_underlying(m.auth));
	ins.bind(":r", std::to_underlying(m.replication));
	ins.bind(":c", static_cast<std::int64_t>(std::time(nullptr)));
	ins.execute();
	LOG_INFO("storage modes persisted [mode={}, auth={}] (rsid={})", int(m.mode), int(m.auth), log_id);
	return m;
}

}

storage::storage(protocol::storage_id id, storage_config config, std::optional<storage_modes> create_modes,
	crypto::public_key_access* keys, crypto::private_data_access* private_data)
: config_(std::move(config))
, id_(std::move(id))
, private_data_(private_data)
{
	std::string path = config_.storage_root_path() + "/" + to_hex(id_);
	std::string db = path + "/storage.db";
	LOG_INFO("Constructing storage using path: {}", db);

	//make sure the path exists, this does nothing if it already does
	std::filesystem::create_directories(path);

	auto db_conn = database::sqlite::create_sqlite_connection(db);
	modes_ = load_or_create_modes(*db_conn, create_modes, to_hex(id_));
	chain_sync_config sync_config{modes_.mode, modes_.auth, to_hex(id_)};

	sync_ = std::make_unique<chain_sync>(db_conn, sync_config, keys);
	heads_ = std::make_unique<storage_heads>(db_conn);
	if(private_data_) {
		if(auto key = private_data_->my_private_key()) {
			own_id_ = key->id();
		}
	}
}

std::vector<origin_head> storage::heads() const {
	std::unique_lock l{mutex_};
	std::vector<origin_head> ret;
	if(own_id_.is_valid() && sync_->log().head().is_valid()) {
		// the own head is derived live from the log so it cannot go stale; term 0 until phase 6
		ret.push_back(origin_head{own_id_, 0, sync_->log().head()});
	}
	for(auto& head : heads_->all()) {
		if(head.origin != own_id_) {
			ret.push_back(std::move(head));
		}
	}
	return ret;
}

sequence_number storage::current_sequence_number() const {
	std::unique_lock l{mutex_};
	return sync_->current_sequence_number();
}

std::deque<chain_block> storage::get_records(sequence_number start, sequence_number end) const {
	std::unique_lock l{mutex_};
	return sync_->get_records(start, end);
}

std::optional<block_envelope> storage::make_envelope(chain_block const& block) const {
	std::optional<block_envelope> env;
	if(private_data_) {
		auto key = private_data_->my_private_key();
		if(key) {
			env = block_envelope{block, key->id()};
			env->sign(id_, *key);
		}
	}
	return env;
}

storage::commit_outcome storage::commit_block(chain_block const& cb) {
	std::unique_lock l{mutex_};
	commit_outcome outcome{sync_->commit_block(cb)};
	if(outcome.block) {
		outcome.envelope = make_envelope(outcome.block.value());
		if(outcome.envelope) {
			// keep the signed assignment in the log so replication can serve it later
			sync_->log().store_assignment(outcome.block.value().tag(), *outcome.envelope);
		}
		notify_listeners(outcome.block.value(), outcome.envelope);
	}
	return outcome;
}

void storage::add_listener(std::shared_ptr<connection> const& p) {
	std::unique_lock l{mutex_};
	listeners_[&*p] = p;
}

void storage::notify_listeners(chain_block const& c, std::optional<block_envelope> const& env) {
	for(auto it = listeners_.begin(); it != listeners_.end(); ) {
		auto p = it->second.lock();
		if(p) {
			p->notify(id_, c, env);
			++it;
		} else {
			it = listeners_.erase(it);
		}
	}
}

}

