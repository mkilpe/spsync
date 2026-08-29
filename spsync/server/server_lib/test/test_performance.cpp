#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <spsync/server/server_lib/chain_sync.hpp>
#include <spsync/test/test_block_creator.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>

#include <chrono>
#include <print>

// performance measurements (hidden tag: run explicitly with "[.performance]")

namespace securepath::sync {

using test::test_block_creator;

namespace {

double per_op_us(auto start, auto end, int n) {
	return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(n);
}

}

TEST_CASE("server signature check performance", "[.performance]") {
	int const n = 2000;

	// pure verify: digest + ML-DSA verification over a typical record
	crypto::public_key_cache keys;
	auto key = crypto::generate_private_key();
	keys.insert(key.public_key());

	test_block_creator creator;
	creator.signer = key;
	auto block = creator.test_data_change();

	auto t0 = std::chrono::steady_clock::now();
	for(int i = 0; i != n; ++i) {
		auto err = block.auth().verify(keys, block.record_bytes());
		REQUIRE(!err);
	}
	auto t1 = std::chrono::steady_clock::now();
	std::println("verify only:          {:8.1f} us/op  ({:.0f} ops/s)", per_op_us(t0, t1, n), 1e6/per_op_us(t0, t1, n));

	// full commit path, signed records
	std::remove("perf_signed.db");
	{
		chain_sync sync(database::sqlite::create_sqlite_connection("perf_signed.db"),
			chain_sync_config{sync_mode::allow_all, auth_mode::sign_records}, &keys);
		test_block_creator c2;
		c2.signer = key;
		CHECK(sync.commit_block(c2.test_user_change()));
		std::deque<chain_block> blocks;
		for(int i = 0; i != n; ++i) {
			blocks.push_back(c2.test_data_change());
		}
		t0 = std::chrono::steady_clock::now();
		for(auto&& b : blocks) {
			REQUIRE(sync.commit_block(b));
		}
		t1 = std::chrono::steady_clock::now();
		std::println("commit signed:        {:8.1f} us/op  ({:.0f} ops/s)", per_op_us(t0, t1, n), 1e6/per_op_us(t0, t1, n));
	}

	// full commit path, unsigned (isolates the signature cost)
	std::remove("perf_unsigned.db");
	{
		chain_sync sync(database::sqlite::create_sqlite_connection("perf_unsigned.db"),
			chain_sync_config{sync_mode::allow_all, auth_mode::only_tag});
		test_block_creator c3;
		CHECK(sync.commit_block(c3.test_user_change()));
		std::deque<chain_block> blocks;
		for(int i = 0; i != n; ++i) {
			blocks.push_back(c3.test_data_change());
		}
		t0 = std::chrono::steady_clock::now();
		for(auto&& b : blocks) {
			REQUIRE(sync.commit_block(b));
		}
		t1 = std::chrono::steady_clock::now();
		std::println("commit unsigned:      {:8.1f} us/op  ({:.0f} ops/s)", per_op_us(t0, t1, n), 1e6/per_op_us(t0, t1, n));
	}

	// same commits on an in-memory database: the crypto/logic ceiling without disk fsync
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(":memory:"),
			chain_sync_config{sync_mode::allow_all, auth_mode::sign_records}, &keys);
		test_block_creator c4;
		c4.signer = key;
		CHECK(sync.commit_block(c4.test_user_change()));
		std::deque<chain_block> blocks;
		for(int i = 0; i != n; ++i) {
			blocks.push_back(c4.test_data_change());
		}
		t0 = std::chrono::steady_clock::now();
		for(auto&& b : blocks) {
			REQUIRE(sync.commit_block(b));
		}
		t1 = std::chrono::steady_clock::now();
		std::println("commit signed (mem):  {:8.1f} us/op  ({:.0f} ops/s)", per_op_us(t0, t1, n), 1e6/per_op_us(t0, t1, n));
	}
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(":memory:"),
			chain_sync_config{sync_mode::allow_all, auth_mode::only_tag});
		test_block_creator c5;
		CHECK(sync.commit_block(c5.test_user_change()));
		std::deque<chain_block> blocks;
		for(int i = 0; i != n; ++i) {
			blocks.push_back(c5.test_data_change());
		}
		t0 = std::chrono::steady_clock::now();
		for(auto&& b : blocks) {
			REQUIRE(sync.commit_block(b));
		}
		t1 = std::chrono::steady_clock::now();
		std::println("commit unsigned (mem):{:8.1f} us/op  ({:.0f} ops/s)", per_op_us(t0, t1, n), 1e6/per_op_us(t0, t1, n));
	}

	// signing side for reference (the client pays this)
	t0 = std::chrono::steady_clock::now();
	for(int i = 0; i != n; ++i) {
		auto a = block.auth();
		a.sign(key, block.record_bytes());
	}
	t1 = std::chrono::steady_clock::now();
	std::println("sign only:            {:8.1f} us/op  ({:.0f} ops/s)", per_op_us(t0, t1, n), 1e6/per_op_us(t0, t1, n));

	std::remove("perf_signed.db");
	std::remove("perf_unsigned.db");
}

}
