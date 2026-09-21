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
			it = stores.emplace(sid, std::make_shared<server_data_store>(db, dir / "data", quota, transfer)).first;
		}
		return it->second;
	}

	crypto::public_key_access const& keys() const override { return public_keys; }
	bool trusted_issuer(crypto::public_key_id const& id) const override { return issuers.contains(id); }

	void announce_complete(protocol::storage_id const& sid, data_id const& id) override {
		announced.emplace_back(sid, id);
	}

	time_point now() const override { return clock; }

	/// a complete data in the storage's store, as an upload left it
	void hold(protocol::storage_id const& sid, client_data const& data, std::uint64_t chunks) {
		auto store = acquire_store(sid);
		REQUIRE(store->open_upload(data.descriptor, data.manifest, clock));
		for(std::uint64_t no = 0; no != chunks; ++no) {
			REQUIRE(store->store_chunk(data.descriptor.manifest_digest, no, data.chunks.at(no), clock));
		}
	}

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
	transfer_quota transfer;
	time_point clock{clock_type::now()};
	std::map<protocol::storage_id, std::shared_ptr<server_data_store>> stores;
	std::vector<std::pair<protocol::storage_id, data_id>> announced;
};

/// a connection whose replies are kept instead of sent
struct test_connection : data_connection {
	using data_connection::data_connection;

	using reply = std::variant<protocol::data_hello_reply, protocol::upload_data_manifest_reply, protocol::upload_data_chunk_reply
		, protocol::download_data_open_reply, protocol::download_data_piece_reply>;

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
		d.chunk_size = chunk_size_range.highest + 1;
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
		conn.handle(protocol::upload_data_chunk{1, sid, id, 0, 0, data.chunks.at(0)});
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
		conn.handle(protocol::upload_data_chunk{4, sid, id, 0, 0, junk});
		CHECK(is_error(conn.take<protocol::upload_data_chunk_reply>().error, protocol::errc::invalid_data_chunk));

		// the upload is of this storage: the same data id under another one was never opened
		conn.handle(protocol::upload_data_chunk{5, securepath::test::random_octet_vector(16), id, 0, 0, data.chunks.at(0)});
		CHECK(is_error(conn.take<protocol::upload_data_chunk_reply>().error, protocol::errc::no_such_upload));

		for(std::uint64_t no : {0u, 2u}) {
			conn.handle(protocol::upload_data_chunk{6, sid, id, no, 0, data.chunks.at(no)});
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

	conn.handle(protocol::upload_data_chunk{1, sid, id, 1, 0, data.chunks.at(1)});
	CHECK(is_error(conn.take<protocol::upload_data_chunk_reply>().error, protocol::errc::no_such_upload));

	conn.handle(protocol::upload_data_manifest{2, ticket, data.manifest});
	auto const resumed = conn.take<protocol::upload_data_manifest_reply>();
	REQUIRE(!resumed.error);
	have_bitmap const have{5, resumed.have};
	CHECK(have.count() == 2);
	CHECK(have.test(0));
	CHECK(have.test(2));

	for(std::uint64_t no : {1u, 3u, 4u}) {
		conn.handle(protocol::upload_data_chunk{3, sid, id, no, 0, data.chunks.at(no)});
		auto const reply = conn.take<protocol::upload_data_chunk_reply>();
		CHECK(!reply.error);
		CHECK(reply.complete == (no == 4));
	}

	// RD13: the record servers hear of it once
	REQUIRE(context.announced.size() == 1);
	CHECK(context.announced[0] == std::pair{sid, id});
	CHECK(context.stores.at(sid)->find(id)->state == record_data_state::in_sync);
}

// a chunk arrives in pieces: appended to a staged file, verified when the last piece is
// in. Whatever breaks the order loses the chunk, and nothing of it is kept
TEST_CASE("data connection takes chunks in pieces", "[unit]") {
	test_data_context context;
	auto const member = crypto::generate_private_key().id();
	auto const sid = securepath::test::random_octet_vector(16);
	auto const data = make_data(2500);
	auto const& id = data.descriptor.manifest_digest;
	REQUIRE(data.chunks.size() == 5);
	auto const staging = test_root / to_hex(sid) / "data" / ".staging";

	auto conn = std::make_unique<test_connection>(context);
	REQUIRE(!conn->on_connect(protocol::data_hello{}, member));
	conn->handle(protocol::upload_data_manifest{1, context.ticket(sid, data.descriptor, member), data.manifest});
	conn->replies.clear();

	/// send [from, to) of a chunk as one piece; the reply
	auto const piece = [&](std::uint64_t chunk_no, std::size_t from, std::size_t to, octet_vector const* bytes = nullptr) {
		auto const& chunk = bytes ? *bytes : data.chunks.at(chunk_no);
		conn->handle(protocol::upload_data_chunk{9, sid, id, chunk_no, from, octet_vector(chunk.begin() + from, chunk.begin() + to)});
		return conn->take<protocol::upload_data_chunk_reply>();
	};
	auto const chunk_size = data.chunks.at(0).size();
	auto const held = [&] { return context.stores.at(sid)->find(id)->have.count(); };

	// in order: nothing is held before the last piece
	CHECK(!piece(0, 0, 400).error);
	CHECK(!piece(0, 400, 800).error);
	CHECK(held() == 0);
	auto const last = piece(0, 800, chunk_size);
	CHECK(!last.error);
	CHECK(!last.complete);
	CHECK(held() == 1);
	CHECK(context.stores.at(sid)->read_chunk(id, 0) == data.chunks.at(0));
	CHECK(std::filesystem::is_empty(staging));

	// two chunks interleaved, as a window sends them
	CHECK(!piece(1, 0, 500).error);
	CHECK(!piece(2, 0, 500).error);
	CHECK(!piece(1, 500, chunk_size).error);
	CHECK(!piece(2, 500, chunk_size).error);
	CHECK(held() == 3);

	// a gap loses the chunk: also the piece that would have been next is refused
	CHECK(!piece(3, 0, 300).error);
	CHECK(is_error(piece(3, 600, 900).error, protocol::errc::invalid_data_chunk));
	CHECK(is_error(piece(3, 300, 600).error, protocol::errc::invalid_data_chunk));
	CHECK(std::filesystem::is_empty(staging));
	// a piece in the middle of a chunk nobody started
	CHECK(is_error(piece(4, 300, 600).error, protocol::errc::invalid_data_chunk));
	// more octets than the chunk has
	CHECK(!piece(3, 0, 300).error);
	auto overlong = data.chunks.at(3);
	overlong.resize(chunk_size + 10);
	CHECK(is_error(piece(3, 300, chunk_size + 10, &overlong).error, protocol::errc::invalid_data_chunk));
	// a chunk the manifest does not name
	CHECK(is_error(piece(5, 0, 100, &data.chunks.at(0)).error, protocol::errc::invalid_data_chunk));
	CHECK(held() == 3);

	// the wrong bytes show when the last piece is in: nothing of the chunk is kept
	auto junk = data.chunks.at(3);
	junk[100] ^= 0x01;
	CHECK(!piece(3, 0, 500, &junk).error);
	CHECK(is_error(piece(3, 500, chunk_size, &junk).error, protocol::errc::invalid_data_chunk));
	CHECK(held() == 3);
	CHECK(std::filesystem::is_empty(staging));

	// a piece at offset 0 starts the chunk over
	CHECK(!piece(3, 0, 500).error);
	CHECK(!piece(3, 0, 700).error);
	CHECK(!piece(3, 700, chunk_size).error);
	CHECK(held() == 4);

	// a piece above what a packet may carry
	octet_vector const huge(protocol::max_data_piece_size + 1);
	conn->handle(protocol::upload_data_chunk{9, sid, id, 4, 0, huge});
	CHECK(is_error(conn->take<protocol::upload_data_chunk_reply>().error, protocol::errc::invalid_data_chunk));

	// the connection goes with a chunk half way: its pieces go with it, the chunks stay
	// (chunk 4 is the short tail of the data)
	REQUIRE(data.chunks.at(4).size() > 50);
	CHECK(!piece(4, 0, 50).error);
	CHECK(!std::filesystem::is_empty(staging));
	conn.reset();
	CHECK(std::filesystem::is_empty(staging));
	CHECK(held() == 4);
	CHECK(context.announced.empty());

	// the next connection finishes the data
	test_connection again{context};
	REQUIRE(!again.on_connect(protocol::data_hello{}, member));
	again.replies.clear();
	again.handle(protocol::upload_data_manifest{1, context.ticket(sid, data.descriptor, member), data.manifest});
	auto const resumed = again.take<protocol::upload_data_manifest_reply>();
	CHECK(have_bitmap{5, resumed.have}.first_missing() == 4);
	again.handle(protocol::upload_data_chunk{2, sid, id, 4, 0, data.chunks.at(4)});
	auto const done = again.take<protocol::upload_data_chunk_reply>();
	CHECK(!done.error);
	CHECK(done.complete);
	CHECK(context.announced.size() == 1);
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

// RDS 6: a download is opened with a download ticket and answered with the manifest and
// what is held; the pieces come from the held chunks only
TEST_CASE("data connection download", "[unit]") {
	test_data_context context;
	auto const member = crypto::generate_private_key().id();
	auto const sid = securepath::test::random_octet_vector(16);
	auto const data = make_data(4500);
	auto const& id = data.descriptor.manifest_digest;
	// an upload in progress: three of the five chunks are here
	context.hold(sid, data, 3);

	test_connection conn{context};
	REQUIRE(!conn.on_connect(protocol::data_hello{}, member));
	conn.replies.clear();
	auto const chunk_size = static_cast<std::uint32_t>(data.chunks.at(0).size());

	// nothing without an opened download
	conn.handle(protocol::download_data_piece{1, sid, id, 0, 0, 100});
	CHECK(is_error(conn.take<protocol::download_data_piece_reply>().error, protocol::errc::data_not_held));

	// an upload ticket opens no download, a download ticket no upload
	conn.handle(protocol::download_data_open{2, context.ticket(sid, data.descriptor, member, data_right::upload)});
	CHECK(is_error(conn.take<protocol::download_data_open_reply>().error, protocol::errc::invalid_data_ticket));
	auto const ticket = context.ticket(sid, data.descriptor, member, data_right::download);
	conn.handle(protocol::upload_data_manifest{3, ticket, data.manifest});
	CHECK(is_error(conn.take<protocol::upload_data_manifest_reply>().error, protocol::errc::invalid_data_ticket));

	// a data that is not here, a descriptor that is not the one it was uploaded with
	auto const other = make_data(100);
	conn.handle(protocol::download_data_open{4, context.ticket(sid, other.descriptor, member, data_right::download)});
	CHECK(is_error(conn.take<protocol::download_data_open_reply>().error, protocol::errc::data_not_held));
	auto contradicting = data.descriptor;
	contradicting.enc_size += 1;
	conn.handle(protocol::download_data_open{5, context.ticket(sid, contradicting, member, data_right::download)});
	CHECK(is_error(conn.take<protocol::download_data_open_reply>().error, protocol::errc::data_not_held));

	conn.handle(protocol::download_data_open{6, ticket});
	auto const opened = conn.take<protocol::download_data_open_reply>();
	REQUIRE(!opened.error);
	CHECK(opened.cid == 6);
	CHECK(opened.sid == sid);
	CHECK(opened.manifest == data.manifest);
	have_bitmap const have{5, opened.have};
	CHECK(have.count() == 3);
	CHECK(have.first_missing() == 3);

	auto const piece = [&](std::uint64_t chunk_no, std::uint64_t offset, std::uint32_t size) {
		conn.handle(protocol::download_data_piece{7, sid, id, chunk_no, offset, size});
		return conn.take<protocol::download_data_piece_reply>();
	};

	// a whole chunk in pieces
	octet_vector assembled;
	for(std::uint32_t offset = 0; offset < chunk_size; offset += 400) {
		auto const reply = piece(1, offset, std::min<std::uint32_t>(400, chunk_size - offset));
		REQUIRE(!reply.error);
		assembled.insert(assembled.end(), reply.bytes.begin(), reply.bytes.end());
	}
	CHECK(assembled == data.chunks.at(1));

	// a chunk that is not here yet, ranges outside a chunk, no octets, more than a piece
	CHECK(is_error(piece(3, 0, 100).error, protocol::errc::data_not_held));
	CHECK(is_error(piece(9, 0, 100).error, protocol::errc::data_not_held));
	CHECK(is_error(piece(0, chunk_size - 10, 11).error, protocol::errc::data_not_held));
	CHECK(is_error(piece(0, chunk_size, 1).error, protocol::errc::data_not_held));
	CHECK(is_error(piece(0, 0, 0).error, protocol::errc::data_not_held));
	CHECK(is_error(piece(0, 0, protocol::max_data_piece_size + 1).error, protocol::errc::data_not_held));
	CHECK(!piece(0, chunk_size - 10, 10).error);

	// the download is of this storage
	conn.handle(protocol::download_data_piece{8, securepath::test::random_octet_vector(16), id, 0, 0, 100});
	CHECK(is_error(conn.take<protocol::download_data_piece_reply>().error, protocol::errc::data_not_held));
}

// RD10: the transfer quota - served octets per storage and window; a refusal names the wait
TEST_CASE("data connection transfer quota", "[unit]") {
	test_data_context context;
	context.transfer = transfer_quota{2500, 600s};
	auto const member = crypto::generate_private_key().id();
	auto const sid = securepath::test::random_octet_vector(16);
	auto const data = make_data(4500);
	auto const& id = data.descriptor.manifest_digest;
	context.hold(sid, data, 5);

	test_connection conn{context};
	REQUIRE(!conn.on_connect(protocol::data_hello{}, member));
	conn.handle(protocol::download_data_open{1, context.ticket(sid, data.descriptor, member, data_right::download)});
	REQUIRE(!conn.take<protocol::data_hello_reply>().error);
	REQUIRE(!conn.take<protocol::download_data_open_reply>().error);

	auto const piece = [&](std::uint64_t chunk_no) {
		conn.handle(protocol::download_data_piece{2, sid, id, chunk_no, 0, 1000});
		return conn.take<protocol::download_data_piece_reply>();
	};
	CHECK(!piece(0).error);
	CHECK(!piece(1).error);
	auto const refused = piece(2);
	CHECK(is_error(refused.error, protocol::errc::data_transfer_quota_exceeded));
	CHECK(refused.bytes.empty());
	CHECK(refused.retry_after > 0);
	CHECK(refused.retry_after <= 600);
	// what does not fit is not counted: a smaller piece still goes
	conn.handle(protocol::download_data_piece{3, sid, id, 2, 0, 500});
	CHECK(!conn.take<protocol::download_data_piece_reply>().error);

	// the next window serves again
	context.clock += std::chrono::seconds{refused.retry_after};
	CHECK(!piece(2).error);
	CHECK(!piece(3).error);
	CHECK(is_error(piece(0).error, protocol::errc::data_transfer_quota_exceeded));

	// another storage has its own budget
	auto const other_sid = securepath::test::random_octet_vector(16);
	context.hold(other_sid, data, 5);
	conn.handle(protocol::download_data_open{4, context.ticket(other_sid, data.descriptor, member, data_right::download)});
	REQUIRE(!conn.take<protocol::download_data_open_reply>().error);
	conn.handle(protocol::download_data_piece{5, other_sid, id, 0, 0, 1000});
	CHECK(!conn.take<protocol::download_data_piece_reply>().error);
}

}
