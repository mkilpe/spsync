#include "storage.hpp"
#include "connection.hpp"

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <filesystem>

namespace securepath::sync {

storage::storage(protocol::storage_id id, storage_config config)
: config_(std::move(config))
, id_(std::move(id))
{
	std::string path = config_.storage_root_path() + "/" + to_hex(id_);
	std::string db = path + "/storage.db";
	LOG_INFO("Constructing storage using path: %", db);

	//make sure the path exists, this does nothing if it already does
	std::filesystem::create_directories(path);

	auto db_conn = database::sqlite::create_sqlite_connection(db);
	//t: read from db
	chain_sync_config sync_config{sync_mode::require_all_seen, to_hex(id_)};

	sync_ = std::make_unique<chain_sync>(db_conn, sync_config);
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

