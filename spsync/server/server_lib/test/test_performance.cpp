#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <spsync/server/server_lib/chain_sync.hpp>
#include <spsync/test/test_block_creator.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>

#include <chrono>
#include <deque>
#include <print>
#include <string>
#include <string_view>

// performance measurements (hidden tag: run explicitly with "[.performance]")

namespace securepath::sync {

using test::test_block_creator;

namespace {

double per_op_us(auto start, auto end, int n) {
	return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(n);
}

/// one line of the report
void report(std::string_view what, double us) {
	std::println("{:22}{:8.1f} us/op  ({:.0f} ops/s)", what, us, 1e6 / us);
}

/// a block creator signing with the key
test_block_creator signing(crypto::private_key const& key) {
	test_block_creator creator;
	creator.signer = key;
	return creator;
}

/// the time per commit of n data changes of the creator on a fresh chain in the database
double commit_us(std::string const& db, auth_mode mode, crypto::public_key_access* keys, test_block_creator creator, int n) {
	chain_sync sync(database::sqlite::create_sqlite_connection(db), chain_sync_config{sync_mode::allow_all, mode}, keys);
	CHECK(sync.commit_block(creator.test_user_change()));
	std::deque<chain_block> blocks;
	for(int i = 0; i != n; ++i) {
		blocks.push_back(creator.test_data_change());
	}
	auto const t0 = std::chrono::steady_clock::now();
	for(auto&& b : blocks) {
		REQUIRE(sync.commit_block(b));
	}
	return per_op_us(t0, std::chrono::steady_clock::now(), n);
}

}

TEST_CASE("server signature check performance", "[.performance]") {
	int const n = 2000;

	// pure verify: digest + ML-DSA verification over a typical record
	crypto::public_key_cache keys;
	auto key = crypto::generate_private_key();
	keys.insert(key.public_key());
	auto block = signing(key).test_data_change();
	auto t0 = std::chrono::steady_clock::now();
	for(int i = 0; i != n; ++i) {
		auto err = block.auth().verify(keys, block.record_bytes());
		REQUIRE(!err);
	}
	report("verify only:", per_op_us(t0, std::chrono::steady_clock::now(), n));

	// full commit path, signed records, then unsigned (isolates the signature cost)
	std::remove("perf_signed.db");
	std::remove("perf_unsigned.db");
	report("commit signed:", commit_us("perf_signed.db", auth_mode::sign_records, &keys, signing(key), n));
	report("commit unsigned:", commit_us("perf_unsigned.db", auth_mode::only_tag, nullptr, test_block_creator{}, n));

	// same commits on an in-memory database: the crypto/logic ceiling without disk fsync
	report("commit signed (mem):", commit_us(":memory:", auth_mode::sign_records, &keys, signing(key), n));
	report("commit unsigned (mem):", commit_us(":memory:", auth_mode::only_tag, nullptr, test_block_creator{}, n));

	// signing side for reference (the client pays this)
	t0 = std::chrono::steady_clock::now();
	for(int i = 0; i != n; ++i) {
		auto a = block.auth();
		a.sign(key, block.record_bytes());
	}
	report("sign only:", per_op_us(t0, std::chrono::steady_clock::now(), n));

	std::remove("perf_signed.db");
	std::remove("perf_unsigned.db");
}

}
