#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/server/server_lib/data_connection.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/serialisation/util.hpp>

#include <deque>
#include <filesystem>
#include <map>
#include <set>
#include <variant>

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

std::filesystem::path const test_root = "data_connection_test";

struct client_data {
	data_descriptor descriptor;
	data_manifest manifest;
	std::map<std::uint64_t, octet_vector> chunks;
};

client_data make_data(std::size_t size, std::uint32_t chunk_size = 1000) {
	encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
	client_data ret;
	data_encryptor enc(key, chunk_size, [&](std::uint64_t no, octet_vector const& c) { ret.chunks[no] = c; });
	enc.write(securepath::test::random_octet_vector(size));
	auto result = enc.finish();
	ret.descriptor = result.descriptor;
	ret.manifest = result.manifest;
	return ret;
}

/// the data server around a connection: stores under a test directory, a settable clock
struct test_data_context : data_server_context {
	test_data_context() {
		std::filesystem::remove_all(test_root);
		public_keys.insert(record_server.public_key());
		issuers.insert(record_server.id());
	}

	std::shared_ptr<server_data_store> acquire_store(protocol::storage_id const& sid) override {
		auto it = stores.find(sid);
		if(it == stores.end()) {
			auto const dir = test_root / to_hex(sid);
			std::filesystem::create_directories(dir);
			auto db = database::sqlite::create_sqlite_connection((dir / "data.db").string());
			it = stores.emplace(sid, std::make_shared<server_data_store>(db, dir / "data", quota)).first;
		}
		return it->second;
	}

	crypto::public_key_access const& keys() const override { return public_keys; }
	bool trusted_issuer(crypto::public_key_id const& id) const override { return issuers.contains(id); }

	void announce_complete(protocol::storage_id const& sid, data_id const& id) override {
		announced.emplace_back(sid, id);
	}

	time_point now() const override { return clock; }

	data_ticket ticket(protocol::storage_id const& sid, data_descriptor const& d, crypto::public_key_id const& member
		, data_right right = data_right::upload) const {
		data_ticket t{sid, d, member, right, clock + 10min};
		t.sign(record_server);
		return t;
	}

	crypto::private_key record_server{crypto::generate_private_key()};
	crypto::public_key_cache public_keys;
	std::set<crypto::public_key_id> issuers;
	data_quota quota;
	time_point clock{clock_type::now()};
	std::map<protocol::storage_id, std::shared_ptr<server_data_store>> stores;
	std::vector<std::pair<protocol::storage_id, data_id>> announced;
};

/// a connection whose replies are kept instead of sent
struct test_connection : data_connection {
	using data_connection::data_connection;

	using reply = std::variant<protocol::data_hello_reply, protocol::upload_data_manifest_reply, protocol::upload_data_chunk_reply>;

	void send(octet_span s) override {
		serialisation::packet_deserialiser<protocol::d2c_types> deser;
		deser.handle(s, [this](auto const& p) { replies.emplace_back(p); });
	}

	template<typename Reply>
	Reply take() {
		REQUIRE(!replies.empty());
		REQUIRE(std::holds_alternative<Reply>(replies.front()));
		auto ret = std::get<Reply>(replies.front());
		replies.pop_front();
		return ret;
	}

	std::deque<reply> replies;
};

bool is_error(network::net_error const& err, protocol::errc code) {
	return protocol::to_error(err).code() == make_error_code(code);
}

}

TEST_CASE("data connection hello", "[unit]") {
	test_data_context context;
	test_connection conn{context};
	auto const member = crypto::generate_private_key().id();

	protocol::data_hello old_client{7};
	old_client.version = protocol::current_version + 1;
	CHECK(conn.on_connect(old_client, member));
	CHECK(conn.replies.empty());

	CHECK(!conn.on_connect(protocol::data_hello{8}, member));
	auto const reply = conn.take<protocol::data_hello_reply>();
	CHECK(reply.cid == 8);
	CHECK(!reply.error);
}

// RD12: the ticket is the data server's only source of truth
TEST_CASE("data connection refuses bad tickets", "[unit]") {
	test_data_context context;
	test_connection conn{context};
	auto const member = crypto::generate_private_key().id();
	REQUIRE(!conn.on_connect(protocol::data_hello{}, member));
	conn.replies.clear();

	auto const sid = securepath::test::random_octet_vector(16);
	auto const data = make_data(4500);

	auto const refused = [&](data_ticket const& ticket, protocol::errc code) {
		conn.handle(protocol::upload_data_manifest{1, ticket, data.manifest});
		auto const reply = conn.take<protocol::upload_data_manifest_reply>();
		bool const ok = is_error(reply.error, code) && reply.have.empty();
		return ok && context.stores.empty();
	};

	SECTION("unsigned") {
		CHECK(refused(data_ticket{sid, data.descriptor, member, data_right::upload, context.clock + 10min}, protocol::errc::invalid_data_ticket));
	}
	SECTION("signed by somebody the keys do not know") {
		data_ticket t{sid, data.descriptor, member, data_right::upload, context.clock + 10min};
		t.sign(crypto::generate_private_key());
		CHECK(refused(t, protocol::errc::invalid_data_ticket));
	}
	SECTION("signed by a known key that is no record server of this data server") {
		auto const other = crypto::generate_private_key();
		context.public_keys.insert(other.public_key());
		data_ticket t{sid, data.descriptor, member, data_right::upload, context.clock + 10min};
		t.sign(other);
		CHECK(refused(t, protocol::errc::invalid_data_ticket));
	}
	SECTION("issued to another member") {
		CHECK(refused(context.ticket(sid, data.descriptor, crypto::generate_private_key().id()), protocol::errc::invalid_data_ticket));
	}
	SECTION("a download ticket") {
		CHECK(refused(context.ticket(sid, data.descriptor, member, data_right::download), protocol::errc::invalid_data_ticket));
	}
	SECTION("expired") {
		auto const t = context.ticket(sid, data.descriptor, member);
		context.clock += 11min;
		CHECK(refused(t, protocol::errc::data_ticket_expired));
	}
	SECTION("a descriptor no chunk of which fits a frame") {
		auto d = data.descriptor;
		d.chunk_size = max_chunk_size + 1;
		CHECK(refused(context.ticket(sid, d, member), protocol::errc::invalid_data_ticket));
		d.chunk_size = 0;
		CHECK(refused(context.ticket(sid, d, member), protocol::errc::invalid_data_ticket));
	}
	SECTION("no storage") {
		CHECK(refused(context.ticket({}, data.descriptor, member), protocol::errc::invalid_data_ticket));
	}
}

// RDS 4: resume reply, junk chunk rejected, announcement after completion
TEST_CASE("data connection upload", "[unit]") {
	test_data_context context;
	auto const member = crypto::generate_private_key().id();
	auto const sid = securepath::test::random_octet_vector(16);
	auto const data = make_data(4500);
	auto const& id = data.descriptor.manifest_digest;
	auto const ticket = context.ticket(sid, data.descriptor, member);

	{
		test_connection conn{context};
		REQUIRE(!conn.on_connect(protocol::data_hello{}, member));
		conn.replies.clear();

		// a chunk before any manifest
		conn.handle(protocol::upload_data_chunk{1, sid, id, 0, data.chunks.at(0)});
		CHECK(is_error(conn.take<protocol::upload_data_chunk_reply>().error, protocol::errc::no_such_upload));

		// a manifest that is not the ticket's
		auto foreign = data.manifest;
		foreign.chunk_digests[0] = securepath::test::random_octet_vector(64);
		conn.handle(protocol::upload_data_manifest{2, ticket, foreign});
		CHECK(is_error(conn.take<protocol::upload_data_manifest_reply>().error, protocol::errc::invalid_data_manifest));

		conn.handle(protocol::upload_data_manifest{3, ticket, data.manifest});
		auto const opened = conn.take<protocol::upload_data_manifest_reply>();
		CHECK(opened.cid == 3);
		CHECK(opened.sid == sid);
		CHECK(!opened.error);
		CHECK(have_bitmap{5, opened.have}.count() == 0);

		// junk
		auto junk = data.chunks.at(0);
		junk.back() ^= 0x01;
		conn.handle(protocol::upload_data_chunk{4, sid, id, 0, junk});
		CHECK(is_error(conn.take<protocol::upload_data_chunk_reply>().error, protocol::errc::invalid_data_chunk));

		// the upload is of this storage: the same data id under another one was never opened
		conn.handle(protocol::upload_data_chunk{5, securepath::test::random_octet_vector(16), id, 0, data.chunks.at(0)});
		CHECK(is_error(conn.take<protocol::upload_data_chunk_reply>().error, protocol::errc::no_such_upload));

		for(std::uint64_t no : {0u, 2u}) {
			conn.handle(protocol::upload_data_chunk{6, sid, id, no, data.chunks.at(no)});
			auto const reply = conn.take<protocol::upload_data_chunk_reply>();
			CHECK(!reply.error);
			CHECK(!reply.complete);
		}
		CHECK(context.announced.empty());
	}

	// another connection, e.g. after the first one dropped: the manifest reply is the resume point
	test_connection conn{context};
	REQUIRE(!conn.on_connect(protocol::data_hello{}, member));
	conn.replies.clear();

	conn.handle(protocol::upload_data_chunk{1, sid, id, 1, data.chunks.at(1)});
	CHECK(is_error(conn.take<protocol::upload_data_chunk_reply>().error, protocol::errc::no_such_upload));

	conn.handle(protocol::upload_data_manifest{2, ticket, data.manifest});
	auto const resumed = conn.take<protocol::upload_data_manifest_reply>();
	REQUIRE(!resumed.error);
	have_bitmap const have{5, resumed.have};
	CHECK(have.count() == 2);
	CHECK(have.test(0));
	CHECK(have.test(2));

	for(std::uint64_t no : {1u, 3u, 4u}) {
		conn.handle(protocol::upload_data_chunk{3, sid, id, no, data.chunks.at(no)});
		auto const reply = conn.take<protocol::upload_data_chunk_reply>();
		CHECK(!reply.error);
		CHECK(reply.complete == (no == 4));
	}

	// RD13: the record servers hear of it once
	REQUIRE(context.announced.size() == 1);
	CHECK(context.announced[0] == std::pair{sid, id});
	CHECK(context.stores.at(sid)->find(id)->state == record_data_state::in_sync);
}

// RD10: quota errors reach the client as such
TEST_CASE("data connection quota errors", "[unit]") {
	test_data_context context;
	auto const small = make_data(100);
	auto const big = make_data(20000);
	context.quota = data_quota{10000, small.descriptor.enc_size};

	auto const member = crypto::generate_private_key().id();
	auto const sid = securepath::test::random_octet_vector(16);
	test_connection conn{context};
	REQUIRE(!conn.on_connect(protocol::data_hello{}, member));
	conn.replies.clear();

	conn.handle(protocol::upload_data_manifest{1, context.ticket(sid, big.descriptor, member), big.manifest});
	CHECK(is_error(conn.take<protocol::upload_data_manifest_reply>().error, protocol::errc::data_too_big));

	conn.handle(protocol::upload_data_manifest{2, context.ticket(sid, small.descriptor, member), small.manifest});
	CHECK(!conn.take<protocol::upload_data_manifest_reply>().error);

	auto const another = make_data(100);
	conn.handle(protocol::upload_data_manifest{3, context.ticket(sid, another.descriptor, member), another.manifest});
	CHECK(is_error(conn.take<protocol::upload_data_manifest_reply>().error, protocol::errc::data_quota_exceeded));

	// the quota is per storage
	auto const other_sid = securepath::test::random_octet_vector(16);
	conn.handle(protocol::upload_data_manifest{4, context.ticket(other_sid, another.descriptor, member), another.manifest});
	CHECK(!conn.take<protocol::upload_data_manifest_reply>().error);
}

}
