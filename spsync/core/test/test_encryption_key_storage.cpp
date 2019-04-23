#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <spsync/core/encryption_key_storage.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/octet_vector.hpp>

namespace securepath::sync::util {

std::string const db_name = "encryption_key_storage_test.db";

void remove_database_test_db() {
	std::remove(db_name.c_str());
}

TEST_CASE("encryption_key_storage", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);
	encryption_key_storage storage(db_conn);

	CHECK_THROWS(storage.current_key());
	CHECK(!storage.find(sequence_number{1}));
	encryption_key key{1, to_octet_vector("test")};
	storage.insert(key);
	CHECK(storage.current_key() == key);
	auto res = storage.find(sequence_number{1});
	REQUIRE(res);
	CHECK(*res == key);
	CHECK(!storage.find(sequence_number{0}));
	CHECK(!storage.find(sequence_number{2}));

	encryption_key new_key{2, to_octet_vector("test second")};
	storage.insert(new_key);
	CHECK(storage.current_key() == new_key);

	auto res2 = storage.find(sequence_number{2});
	REQUIRE(res2);
	CHECK(*res2 == new_key);

	auto res1 = storage.find(sequence_number{1});
	REQUIRE(res1);
	CHECK(*res1 == key);
}

}
