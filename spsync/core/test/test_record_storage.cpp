#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <spsync/core/record_storage.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/octet_vector.hpp>

namespace securepath::sync::util {

std::string const db_name = "record_storage_test.db";

static void remove_database_test_db() {
	std::remove(db_name.c_str());
}

TEST_CASE("record_storage", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	//todo
}

}
