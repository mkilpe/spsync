#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/server/server_lib/chain_log.hpp>

#include <spsync/test/test_block_creator.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/database/sqlite/connection.hpp>

namespace securepath::sync {

using test::test_block_creator;
std::string const chain_log_db = "chain_log_test.db";

static void remove_chain_log_db() {
	std::remove(chain_log_db.c_str());
}

TEST_CASE("chain_log append and get", "[unit]") {
	remove_chain_log_db();
	chain_log log(database::sqlite::create_sqlite_connection(chain_log_db));

	CHECK(!log.head().is_valid());
	CHECK(log.get({}, {}, 100).empty());

	test_block_creator creator;
	auto b1 = creator.test_user_change();
	log.append(block_envelope{b1, {}});
	CHECK(log.head() == b1.id());

	auto b2 = creator.test_data_change();
	log.append(block_envelope{b2, {}});
	auto b3 = creator.test_data_change();

	// a block that does not extend the head is refused
	auto bad = b3;
	bad.set_sequence_and_parent_hash(sequence_number{5}, b2.hash());
	CHECK_THROWS(log.append(block_envelope{bad, {}}));
	bad.set_sequence_and_parent_hash(sequence_number{3}, securepath::test::random_octet_vector(16));
	CHECK_THROWS(log.append(block_envelope{bad, {}}));

	log.append(block_envelope{b3, {}});
	CHECK(log.head() == b3.id());

	// the range defaults to the whole log; without a signature the envelopes are unsigned wrappers
	auto envs = log.get({}, {}, 100);
	REQUIRE(envs.size() == 3);
	CHECK(envs[0].block().tag() == b1.tag());
	CHECK(envs[2].block().tag() == b3.tag());
	CHECK(!envs[2].is_signed());
	CHECK(envs[2].block().id() == b3.id());

	// explicit range and the max cap
	CHECK(log.get(sequence_number{2}, sequence_number{3}, 100).size() == 2);
	CHECK(log.get({}, {}, 2).size() == 2);

	CHECK(log.find_by_tag(b2.tag()));
	CHECK(log.find_by_tag(b2.tag())->block_id() == b2.id());
	CHECK(!log.find_by_tag(securepath::test::random_octet_vector(16)));

	auto op = b2.deserialise_to<data_change_record>().op_id();
	CHECK(log.find_by_op_id(op) == log.find_by_tag(b2.tag()));
}

TEST_CASE("chain_log persists signed envelopes", "[unit]") {
	remove_chain_log_db();
	auto server_key = crypto::generate_private_key();
	crypto::public_key_cache keys;
	keys.insert(server_key.public_key());
	octet_vector const sid = securepath::test::random_octet_vector(8);

	test_block_creator creator;
	auto b1 = creator.test_user_change();
	auto b2 = creator.test_user_change();
	{
		chain_log log(database::sqlite::create_sqlite_connection(chain_log_db));
		block_envelope env{b1, server_key.id()};
		env.sign(sid, server_key);
		log.append(env);

		// the local commit path appends first and signs the assignment afterwards
		log.append(block_envelope{b2, {}});
		block_envelope late{b2, server_key.id()};
		late.sign(sid, server_key);
		log.store_assignment(b2.tag(), late);
		CHECK_THROWS(log.store_assignment(securepath::test::random_octet_vector(16), late));
	}
	{
		// the head and the signed envelopes survive reopen
		chain_log log(database::sqlite::create_sqlite_connection(chain_log_db));
		CHECK(log.head() == b2.id());
		auto envs = log.get({}, {}, 10);
		REQUIRE(envs.size() == 2);
		for(auto const& env : envs) {
			CHECK(env.is_signed());
			CHECK(env.origin() == server_key.id());
			CHECK(!env.verify(sid, keys));
		}
		CHECK(envs[0].block().id() == b1.id());
		CHECK(envs[1].block().id() == b2.id());
	}
}

TEST_CASE("chain_log truncate recomputes head", "[unit]") {
	remove_chain_log_db();
	chain_log log(database::sqlite::create_sqlite_connection(chain_log_db));

	test_block_creator creator;
	auto b1 = creator.test_user_change();
	log.append(block_envelope{b1, {}});
	auto rewind = creator; // creator state on top of b1
	auto b2 = creator.test_data_change();
	log.append(block_envelope{b2, {}});
	auto b3 = creator.test_data_change();
	log.append(block_envelope{b3, {}});

	auto removed = log.truncate_from(sequence_number{2});
	REQUIRE(removed.size() == 2);
	CHECK(removed[0].tag() == b2.tag());
	CHECK(log.head() == b1.id());

	// the log extends from the recomputed head again
	auto b2b = rewind.test_data_change();
	log.append(block_envelope{b2b, {}});
	CHECK(log.head() == b2b.id());
}

TEST_CASE("chain_log find_divergence", "[unit]") {
	remove_chain_log_db();
	chain_log log(database::sqlite::create_sqlite_connection(chain_log_db));

	test_block_creator creator;
	auto b1 = creator.test_user_change();
	log.append(block_envelope{b1, {}});
	auto b2 = creator.test_data_change();
	log.append(block_envelope{b2, {}});
	auto b3 = creator.test_data_change();
	log.append(block_envelope{b3, {}});

	// matching heads: no divergence
	CHECK(!log.find_divergence({}).is_valid());
	CHECK(!log.find_divergence({b1.id(), b2.id(), b3.id()}).is_valid());

	// a peer ahead of us is not divergence, we are only behind
	chain_block_id const ahead{sequence_number{4}, securepath::test::random_octet_vector(16)};
	CHECK(!log.find_divergence({ahead}).is_valid());

	// a different hash at a sequence we hold is divergence at that sequence
	chain_block_id const fork2{sequence_number{2}, securepath::test::random_octet_vector(16)};
	chain_block_id const fork3{sequence_number{3}, securepath::test::random_octet_vector(16)};
	CHECK(log.find_divergence({fork2}) == sequence_number{2});

	// the lowest divergent sequence wins regardless of the input order
	CHECK(log.find_divergence({fork3, fork2, b1.id(), ahead}) == sequence_number{2});
	CHECK(log.find_divergence({fork3, b2.id()}) == sequence_number{3});
}

}
