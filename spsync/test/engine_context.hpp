#ifndef SPSYNC_TEST_ENGINE_CONTEXT_HEADER
#define SPSYNC_TEST_ENGINE_CONTEXT_HEADER

#include "comm_test_interface.hpp"
#include "test_progress.hpp"
#include "test_sync_engine.hpp"

#include <spsync/core/encryption_key_storage.hpp>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/rsa.hpp>
#include <securepath/database/sqlite/connection.hpp>

namespace securepath::sync::test {

inline database::connection_ptr create_test_database(std::string const& db_name = "test.db") {
	std::remove(db_name.c_str());
	return database::sqlite::create_sqlite_connection(db_name);
}

class engine_context {
public:

	engine_context() {
		io.set_output(engine);
	}

	void create_initial_record() {
		// set initial key, use hard coded one for testing
		enc_keys.insert(encryption_key{sequence_number{1}, to_octet_vector("12345678901234567890123456789012")});
		users initial;
		initial.add(util::user_access{root_user, util::access_type::user_management_access});
		engine.sync_user_change(initial);
	}

	crypto::private_key root_user_key{crypto::generate_rsa_private_key(1024)};
	util::user_id root_user{root_user_key.id()};

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