#ifndef SPSYNC_TEST_UTIL_HEADER
#define SPSYNC_TEST_UTIL_HEADER

#include <securepath/database/sqlite/connection.hpp>

namespace securepath::sync::test {

inline database::connection_ptr create_test_database(std::string const& db_name = "test.db") {
	std::remove(db_name.c_str());
	return database::sqlite::create_sqlite_connection(db_name);
}

}

#endif