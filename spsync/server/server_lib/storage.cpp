#include "storage.hpp"
#include "connection.hpp"

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <spsync/protocol/error.hpp>

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
	ins.bind(":m", static_cast<std::int64_t>(m.mode));
	ins.bind(":a", static_cast<std::int64_t>(m.auth));
	ins.bind(":r", static_cast<std::int64_t>(m.replication));
	ins.bind(":c", static_cast<std::int64_t>(std::time(nullptr)));
	ins.execute();
	LOG_INFO("storage modes persisted [mode={}, auth={}] (rsid={})", int(m.mode), int(m.auth), log_id);
	return m;
}

}

storage::storage(protocol::storage_id id, storage_config config, std::optional<storage_modes> create_modes,
	crypto::public_key_access* keys)
: config_(std::move(config))
, id_(std::move(id))
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
}

sequence_number storage::current_sequence_number() const {
	std::unique_lock l{mutex_};
	return sync_->current_sequence_number();
}

std::deque<chain_block> storage::get_records(sequence_number start, sequence_number end) const {
	std::unique_lock l{mutex_};
	return sync_->get_records(start, end);
}

util::result<chain_block> storage::commit_block(chain_block const& cb) {
	std::unique_lock l{mutex_};
	auto res = sync_->commit_block(cb);
	if(res) {
		notify_listeners(res.value());
	}
	return res;
}

void storage::add_listener(std::shared_ptr<connection> const& p) {
	std::unique_lock l{mutex_};
	listeners_[&*p] = p;
}

void storage::notify_listeners(chain_block const& c) {
	for(auto it = listeners_.begin(); it != listeners_.end(); ) {
		auto p = it->second.lock();
		if(p) {
			p->notify(id_, c);
			++it;
		} else {
			it = listeners_.erase(it);
		}
	}
}

}

