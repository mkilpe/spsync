#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <spsync/core/encryption_key_storage.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/octet_vector.hpp>

namespace securepath::sync::test {

std::string const db_name = "encryption_key_storage_test.db";

static void remove_database_test_db() {
	std::remove(db_name.c_str());
}

using util::sequence_number;

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
	CHECK(storage.export_keys().size() == 2);
}

// concurrent key rotations can collide on a sequence (plan 4.6/D9): both keys are kept,
// the pick for the sequence is deterministic and decryption can try every candidate
TEST_CASE("encryption key storage keeps colliding keys", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);
	encryption_key_storage storage(db_conn);

	encryption_key const a{sequence_number{1}, to_octet_vector("key aaaaaaaaaaaa")};
	encryption_key const b{sequence_number{1}, to_octet_vector("key bbbbbbbbbbbb")};
	storage.insert(a, to_octet_vector("tag1"));
	storage.insert(b, to_octet_vector("tag2"));
	// an identical key is not duplicated
	storage.insert(a, to_octet_vector("tag3"));

	auto all = storage.find_all(sequence_number{1});
	REQUIRE(all.size() == 2);
	CHECK((all[0] == a || all[1] == a));
	CHECK((all[0] == b || all[1] == b));

	// the single pick is deterministic (ordered by the key bytes)
	auto picked = storage.find(sequence_number{1});
	REQUIRE(picked);
	CHECK(*picked == all[0]);
	CHECK(storage.current_key() == all[0]);

	// a newer sequence takes over as current
	encryption_key const c{sequence_number{2}, to_octet_vector("key cccccccccccc")};
	storage.insert(c);
	CHECK(storage.current_key() == c);
	CHECK(storage.find_all(sequence_number{2}).size() == 1);
}

}
