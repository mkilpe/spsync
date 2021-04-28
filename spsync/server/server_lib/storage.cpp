#include "storage.hpp"

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::sync {

storage::storage(protocol::storage_id const& id) {
	//t: later on perhaps parameterise the path, so that it is read from config
	auto db_conn = database::sqlite::create_sqlite_connection(to_hex(id) + "/storage.db");
	//t: read from db
	chain_sync_config sync_config{sync_mode::require_all_seen, to_hex(id)};

	sync_ = std::make_unique<chain_sync>(db_conn, sync_config);
}

}

