#ifndef SPSYNC_TEST_ENGINE_CONTEXT_HEADER
#define SPSYNC_TEST_ENGINE_CONTEXT_HEADER

#include "comm_test_interface.hpp"
#include "test_progress.hpp"
#include "test_sync_engine.hpp"

#include <spsync/core/encryption_key_storage.hpp>
#include <securepath/database/sqlite/connection.hpp>

namespace securepath::sync::test {

inline database::connection_ptr create_test_database(std::string const& db_name = "test.db") {
	std::remove(db_name.c_str());
	return database::sqlite::create_sqlite_connection(db_name);
}

class engine_context {
public:

	database::connection_ptr database{create_test_database()};
	test_progress progress;
	record_storage storage{database};
	comm_test_interface io{progress, storage};
	encryption_key_storage enc_keys{database};
	sync_engine_config engine_config;
	test_sync_engine engine{io, enc_keys, engine_config};
};

}

#endif