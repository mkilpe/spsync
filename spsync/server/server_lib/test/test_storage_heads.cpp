#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/server/server_lib/storage_heads.hpp>

#include <securepath/database/sqlite/connection.hpp>

namespace securepath::sync {
namespace {

std::string const heads_db = "storage_heads_test.db";

void remove_heads_db() {
	std::remove(heads_db.c_str());
}

crypto::public_key_id heads_key_id(std::uint8_t filler) {
	return crypto::public_key_id{octet_vector(32, filler)};
}

origin_head test_head(std::uint8_t origin, std::uint64_t term, std::uint64_t seq) {
	return origin_head{heads_key_id(origin), term
		, chain_block_id{seq, securepath::test::random_octet_vector(16)}};
}

}

TEST_CASE("storage_heads advance and find", "[unit]") {
	remove_heads_db();
	storage_heads heads(database::sqlite::create_sqlite_connection(heads_db));

	CHECK(heads.all().empty());
	CHECK(!heads.find(heads_key_id(1)));

	// only a valid origin and block id can be stored
	CHECK_THROWS(heads.advance(origin_head{{}, 0, chain_block_id{1, octet_vector(4, 1)}}));
	CHECK_THROWS(heads.advance(origin_head{heads_key_id(1), 0, {}}));

	auto const h1 = test_head(1, 0, 3);
	CHECK(heads.advance(h1));
	CHECK(heads.find(h1.origin) == h1);

	// not newer: lower sequence, or the same (term, sequence) under a different hash
	CHECK(!heads.advance(test_head(1, 0, 2)));
	CHECK(!heads.advance(test_head(1, 0, 3)));
	CHECK(heads.find(h1.origin) == h1);

	// a higher sequence advances, a higher term dominates a lower sequence
	auto const h2 = test_head(1, 0, 4);
	CHECK(heads.advance(h2));
	CHECK(heads.find(h1.origin) == h2);
	auto const h3 = test_head(1, 1, 2);
	CHECK(heads.advance(h3));
	CHECK(heads.find(h1.origin) == h3);

	// origins are independent
	auto const other = test_head(2, 0, 1);
	CHECK(heads.advance(other));
	CHECK(heads.find(other.origin) == other);
	CHECK(heads.all().size() == 2);

	heads.remove(h1.origin);
	CHECK(!heads.find(h1.origin));
	CHECK(heads.all() == std::vector{other});
}

TEST_CASE("storage_heads persists over reopen", "[unit]") {
	remove_heads_db();
	auto const h1 = test_head(1, 0, 3);
	auto const h2 = test_head(2, 2, 7);
	{
		storage_heads heads(database::sqlite::create_sqlite_connection(heads_db));
		CHECK(heads.advance(h1));
		CHECK(heads.advance(h2));
	}
	{
		storage_heads heads(database::sqlite::create_sqlite_connection(heads_db));
		CHECK(heads.find(h1.origin) == h1);
		CHECK(heads.find(h2.origin) == h2);
		CHECK(heads.all().size() == 2);
		// the monotonic rule still holds against the persisted state
		CHECK(!heads.advance(test_head(2, 2, 6)));
	}
}

}
