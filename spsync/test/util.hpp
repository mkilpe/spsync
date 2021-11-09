#ifndef SPSYNC_TEST_UTIL_HEADER
#define SPSYNC_TEST_UTIL_HEADER

#include <spsync/core/record_storage.hpp>

#include <securepath/database/sqlite/connection.hpp>

namespace securepath::sync::test {

database::connection_ptr create_test_database(std::string const& db_name = "test.db", bool remove = true);
bool check_record_matches(sequence_number seq, int client_n, record_handle sh, record_handle ch);
bool check_commit_records_equal(sequence_number seq, record_storage const&, record_storage const&);

}

#endif