// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <limits>
#include <securepath/test_frame/test_utils.hpp>
#include <spsync/test/test_record_data.hpp>
#include "data_server_fixtures.hpp"

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

using test::client_data;
using test::is_error;
auto const make_data = [](std::size_t size, std::uint32_t chunk_size = 1000) { return test::make_client_data(size, chunk_size); };

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

	bool admit(crypto::public_key_id const&) override { return true; }
	void leave(crypto::public_key_id const&) override {}

	/// a complete data in the storage's store, as an upload left it
	void hold(protocol::storage_id const& sid, client_data const& data, std::uint64_t chunks) {
		auto store = acquire_store(sid);
		REQUIRE(store->open_upload(data.descriptor, data.manifest, clock));
		for(std::uint64_t no = 0; no != chunks; ++no) {
			REQUIRE(test::store_whole_chunk(*store, data.descriptor.manifest_digest, no, data.chunks.at(no), clock));
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

/// one data of a member in a storage: the context, the member's tickets for it,
/// connections with their hello done
struct data_scene {
	explicit data_scene(std::size_t size) : data(make_data(size)) {}

	/// a connection of the member with its hello done and the reply dropped
	std::unique_ptr<test_connection> connect() {
		auto conn = std::make_unique<test_connection>(context);
		REQUIRE(!conn->on_connect(protocol::data_hello{}, member));
		conn->replies.clear();
		return conn;
	}

	data_ticket ticket(data_right right = data_right::upload) const {
		return context.ticket(sid, data.descriptor, member, right);
	}

	/// the manifest with the upload ticket; the reply
	protocol::upload_data_manifest_reply open_upload(test_connection& conn, protocol::call_id cid) {
		conn.handle(protocol::upload_data_manifest{cid, ticket(), data.manifest});
		return conn.take<protocol::upload_data_manifest_reply>();
	}

	/// a whole chunk as one piece; the reply
	protocol::upload_data_chunk_reply chunk(test_connection& conn, protocol::call_id cid, std::uint64_t no) {
		conn.handle(protocol::upload_data_chunk{cid, sid, id, no, 0, data.chunks.at(no)});
		return conn.take<protocol::upload_data_chunk_reply>();
	}

	/// [from, to) of a chunk (or of the given bytes in its place) as one piece; the reply
	protocol::upload_data_chunk_reply piece(test_connection& conn, std::uint64_t chunk_no, std::size_t from, std::size_t to
		, octet_vector const* bytes = nullptr) {
		auto const& chunk = bytes ? *bytes : data.chunks.at(chunk_no);
		conn.handle(protocol::upload_data_chunk{9, sid, id, chunk_no, from, octet_vector(chunk.begin() + from, chunk.begin() + to)});
		return conn.take<protocol::upload_data_chunk_reply>();
	}

	/// [offset, offset + size) of a held chunk; the reply
	protocol::download_data_piece_reply download_piece(test_connection& conn, std::uint64_t chunk_no, std::uint64_t offset, std::uint32_t size) {
		conn.handle(protocol::download_data_piece{7, sid, id, chunk_no, offset, size});
		return conn.take<protocol::download_data_piece_reply>();
	}

	/// the chunks the storage's store holds of the data
	std::uint64_t held() {
		return context.stores.at(sid)->find(id)->have.count();
	}

public:
	test_data_context context;
	crypto::public_key_id member{crypto::generate_private_key().id()};
	protocol::storage_id sid{securepath::test::random_octet_vector(16)};
	client_data data;
	data_id id{data.descriptor.manifest_digest};
};

/// before the manifest: a chunk is no upload, a manifest that is not the ticket's is refused
void refused_before_manifest(data_scene& s, test_connection& conn) {
	// a chunk before any manifest
	CHECK(is_error(s.chunk(conn, 1, 0).error, protocol::errc::no_such_upload));

	// a manifest that is not the ticket's
	auto foreign = s.data.manifest;
	foreign.chunk_digests[0] = securepath::test::random_octet_vector(64);
	conn.handle(protocol::upload_data_manifest{2, s.ticket(), foreign});
	CHECK(is_error(conn.take<protocol::upload_data_manifest_reply>().error, protocol::errc::invalid_data_manifest));
}

/// after the manifest: junk is refused, and the same data id under another storage was
/// never opened
void refused_after_manifest(data_scene& s, test_connection& conn) {
	// junk
	auto junk = s.data.chunks.at(0);
	junk.back() ^= 0x01;
	conn.handle(protocol::upload_data_chunk{4, s.sid, s.id, 0, 0, junk});
	CHECK(is_error(conn.take<protocol::upload_data_chunk_reply>().error, protocol::errc::invalid_data_chunk));

	// the upload is of this storage: the same data id under another one was never opened
	conn.handle(protocol::upload_data_chunk{5, securepath::test::random_octet_vector(16), s.id, 0, 0, s.data.chunks.at(0)});
	CHECK(is_error(conn.take<protocol::upload_data_chunk_reply>().error, protocol::errc::no_such_upload));
}

/// in order nothing is held before the last piece; two chunks interleaved, as a window
/// sends them: three chunks held
void chunks_from_pieces(data_scene& s, test_connection& conn, std::filesystem::path const& staging) {
	auto const chunk_size = s.data.chunks.at(0).size();
	// in order: nothing is held before the last piece
	CHECK(!s.piece(conn, 0, 0, 400).error);
	CHECK(!s.piece(conn, 0, 400, 800).error);
	CHECK(s.held() == 0);
	auto const last = s.piece(conn, 0, 800, chunk_size);
	CHECK(!last.error);
	CHECK(!last.complete);
	CHECK(s.held() == 1);
	CHECK(s.context.stores.at(s.sid)->chunks().read_chunk(s.id, 0) == s.data.chunks.at(0));
	CHECK(std::filesystem::is_empty(staging));

	// two chunks interleaved, as a window sends them
	CHECK(!s.piece(conn, 1, 0, 500).error);
	CHECK(!s.piece(conn, 2, 0, 500).error);
	CHECK(!s.piece(conn, 1, 500, chunk_size).error);
	CHECK(!s.piece(conn, 2, 500, chunk_size).error);
	CHECK(s.held() == 3);
}

/// whatever breaks the order loses the chunk, and nothing of it is kept; a piece at
/// offset 0 starts the chunk over: the fourth chunk held in the end
void broken_pieces_lose_the_chunk(data_scene& s, test_connection& conn, std::filesystem::path const& staging) {
	auto const chunk_size = s.data.chunks.at(0).size();
	// a gap loses the chunk: also the piece that would have been next is refused
	CHECK(!s.piece(conn, 3, 0, 300).error);
	CHECK(is_error(s.piece(conn, 3, 600, 900).error, protocol::errc::invalid_data_chunk));
	CHECK(is_error(s.piece(conn, 3, 300, 600).error, protocol::errc::invalid_data_chunk));
	CHECK(std::filesystem::is_empty(staging));
	// a piece in the middle of a chunk nobody started
	CHECK(is_error(s.piece(conn, 4, 300, 600).error, protocol::errc::invalid_data_chunk));
	// more octets than the chunk has
	CHECK(!s.piece(conn, 3, 0, 300).error);
	auto overlong = s.data.chunks.at(3);
	overlong.resize(chunk_size + 10);
	CHECK(is_error(s.piece(conn, 3, 300, chunk_size + 10, &overlong).error, protocol::errc::invalid_data_chunk));
	// a chunk the manifest does not name
	CHECK(is_error(s.piece(conn, 5, 0, 100, &s.data.chunks.at(0)).error, protocol::errc::invalid_data_chunk));
	CHECK(s.held() == 3);

	// the wrong bytes show when the last piece is in: nothing of the chunk is kept
	auto junk = s.data.chunks.at(3);
	junk[100] ^= 0x01;
	CHECK(!s.piece(conn, 3, 0, 500, &junk).error);
	CHECK(is_error(s.piece(conn, 3, 500, chunk_size, &junk).error, protocol::errc::invalid_data_chunk));
	CHECK(s.held() == 3);
	CHECK(std::filesystem::is_empty(staging));

	// a piece at offset 0 starts the chunk over
	CHECK(!s.piece(conn, 3, 0, 500).error);
	CHECK(!s.piece(conn, 3, 0, 700).error);
	CHECK(!s.piece(conn, 3, 700, chunk_size).error);
	CHECK(s.held() == 4);
}

/// nothing without an opened download; an upload ticket opens no download, a download
/// ticket no upload; a data that is not here, a descriptor that is not the one it was
/// uploaded with
void download_open_refusals(data_scene& s, test_connection& conn) {
	// nothing without an opened download
	conn.handle(protocol::download_data_piece{1, s.sid, s.id, 0, 0, 100});
	CHECK(is_error(conn.take<protocol::download_data_piece_reply>().error, protocol::errc::data_not_held));

	// an upload ticket opens no download, a download ticket no upload
	conn.handle(protocol::download_data_open{2, s.ticket(data_right::upload)});
	CHECK(is_error(conn.take<protocol::download_data_open_reply>().error, protocol::errc::invalid_data_ticket));
	conn.handle(protocol::upload_data_manifest{3, s.ticket(data_right::download), s.data.manifest});
	CHECK(is_error(conn.take<protocol::upload_data_manifest_reply>().error, protocol::errc::invalid_data_ticket));

	// a data that is not here, a descriptor that is not the one it was uploaded with
	auto const other = make_data(100);
	conn.handle(protocol::download_data_open{4, s.context.ticket(s.sid, other.descriptor, s.member, data_right::download)});
	CHECK(is_error(conn.take<protocol::download_data_open_reply>().error, protocol::errc::data_not_held));
	auto contradicting = s.data.descriptor;
	contradicting.enc_size += 1;
	conn.handle(protocol::download_data_open{5, s.context.ticket(s.sid, contradicting, s.member, data_right::download)});
	CHECK(is_error(conn.take<protocol::download_data_open_reply>().error, protocol::errc::data_not_held));
}

/// the pieces come from the held chunks only: a chunk that is not here yet, ranges outside
/// a chunk, no octets, more than a piece, an offset that wraps the range check
void download_range_refusals(data_scene& s, test_connection& conn) {
	auto const chunk_size = static_cast<std::uint32_t>(s.data.chunks.at(0).size());
	// a chunk that is not here yet, ranges outside a chunk, no octets, more than a piece
	CHECK(is_error(s.download_piece(conn, 3, 0, 100).error, protocol::errc::data_not_held));
	CHECK(is_error(s.download_piece(conn, 9, 0, 100).error, protocol::errc::data_not_held));
	CHECK(is_error(s.download_piece(conn, 0, chunk_size - 10, 11).error, protocol::errc::data_not_held));
	CHECK(is_error(s.download_piece(conn, 0, chunk_size, 1).error, protocol::errc::data_not_held));
	CHECK(is_error(s.download_piece(conn, 0, 0, 0).error, protocol::errc::data_not_held));
	CHECK(is_error(s.download_piece(conn, 0, 0, protocol::max_data_piece_size + 1).error, protocol::errc::data_not_held));
	CHECK(!s.download_piece(conn, 0, chunk_size - 10, 10).error);

	// (review 2026-09-21) an offset that wraps the range check: refused like any other
	// range outside the chunk - it used to pass the check, fail at the file, count as a
	// lost chunk and DELETE it, so a member could empty a data server piece by piece
	auto const huge = std::numeric_limits<std::uint64_t>::max();
	auto const wrapping = [&](std::uint64_t offset, std::uint32_t size) {
		conn.handle(protocol::download_data_piece{9, s.sid, s.id, 0, offset, size});
		return conn.take<protocol::download_data_piece_reply>();
	};
	CHECK(is_error(wrapping(huge, 2).error, protocol::errc::data_not_held));
	CHECK(is_error(wrapping(huge - 5, 10).error, protocol::errc::data_not_held));
	auto const still_there = s.download_piece(conn, 0, 0, chunk_size);
	REQUIRE(!still_there.error);
	CHECK(still_there.bytes == s.data.chunks.at(0));
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
	data_scene s{4500};
	{
		auto conn = s.connect();
		refused_before_manifest(s, *conn);
		auto const opened = s.open_upload(*conn, 3);
		CHECK(opened.cid == 3);
		CHECK(opened.sid == s.sid);
		CHECK(!opened.error);
		CHECK(have_bitmap{5, opened.have}.count() == 0);
		refused_after_manifest(s, *conn);
		for(std::uint64_t no : {0u, 2u}) {
			auto const reply = s.chunk(*conn, 6, no);
			CHECK(!reply.error);
			CHECK(!reply.complete);
		}
		CHECK(s.context.announced.empty());
	}

	// another connection, e.g. after the first one dropped: the manifest reply is the resume point
	auto conn = s.connect();
	CHECK(is_error(s.chunk(*conn, 1, 1).error, protocol::errc::no_such_upload));
	auto const resumed = s.open_upload(*conn, 2);
	REQUIRE(!resumed.error);
	have_bitmap const have{5, resumed.have};
	CHECK(have.count() == 2);
	CHECK(have.test(0));
	CHECK(have.test(2));

	for(std::uint64_t no : {1u, 3u, 4u}) {
		auto const reply = s.chunk(*conn, 3, no);
		CHECK(!reply.error);
		CHECK(reply.complete == (no == 4));
	}

	// RD13: the record servers hear of it once
	REQUIRE(s.context.announced.size() == 1);
	CHECK(s.context.announced[0] == std::pair{s.sid, s.id});
	CHECK(s.context.stores.at(s.sid)->find(s.id)->state == record_data_state::in_sync);
}

// a chunk arrives in pieces: appended to a staged file, verified when the last piece is
// in. Whatever breaks the order loses the chunk, and nothing of it is kept
TEST_CASE("data connection takes chunks in pieces", "[unit]") {
	data_scene s{2500};
	REQUIRE(s.data.chunks.size() == 5);
	auto const staging = test_root / to_hex(s.sid) / "data" / ".staging";
	auto conn = s.connect();
	s.open_upload(*conn, 1);

	chunks_from_pieces(s, *conn, staging);
	broken_pieces_lose_the_chunk(s, *conn, staging);

	// a piece above what a packet may carry
	octet_vector const huge(protocol::max_data_piece_size + 1);
	conn->handle(protocol::upload_data_chunk{9, s.sid, s.id, 4, 0, huge});
	CHECK(is_error(conn->take<protocol::upload_data_chunk_reply>().error, protocol::errc::invalid_data_chunk));

	// the connection goes with a chunk half way: its pieces go with it, the chunks stay
	// (chunk 4 is the short tail of the data)
	REQUIRE(s.data.chunks.at(4).size() > 50);
	CHECK(!s.piece(*conn, 4, 0, 50).error);
	CHECK(!std::filesystem::is_empty(staging));
	conn.reset();
	CHECK(std::filesystem::is_empty(staging));
	CHECK(s.held() == 4);
	CHECK(s.context.announced.empty());

	// the next connection finishes the data
	auto again = s.connect();
	auto const resumed = s.open_upload(*again, 1);
	CHECK(have_bitmap{5, resumed.have}.first_missing() == 4);
	auto const done = s.chunk(*again, 2, 4);
	CHECK(!done.error);
	CHECK(done.complete);
	CHECK(s.context.announced.size() == 1);
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
	data_scene s{4500};
	// an upload in progress: three of the five chunks are here
	s.context.hold(s.sid, s.data, 3);
	auto conn = s.connect();
	auto const chunk_size = static_cast<std::uint32_t>(s.data.chunks.at(0).size());
	download_open_refusals(s, *conn);

	conn->handle(protocol::download_data_open{6, s.ticket(data_right::download)});
	auto const opened = conn->take<protocol::download_data_open_reply>();
	REQUIRE(!opened.error);
	CHECK(opened.cid == 6);
	CHECK(opened.sid == s.sid);
	CHECK(opened.manifest == s.data.manifest);
	have_bitmap const have{5, opened.have};
	CHECK(have.count() == 3);
	CHECK(have.first_missing() == 3);

	// a whole chunk in pieces
	octet_vector assembled;
	for(std::uint32_t offset = 0; offset < chunk_size; offset += 400) {
		auto const reply = s.download_piece(*conn, 1, offset, std::min<std::uint32_t>(400, chunk_size - offset));
		REQUIRE(!reply.error);
		assembled.insert(assembled.end(), reply.bytes.begin(), reply.bytes.end());
	}
	CHECK(assembled == s.data.chunks.at(1));
	download_range_refusals(s, *conn);

	// the download is of this storage
	conn->handle(protocol::download_data_piece{8, securepath::test::random_octet_vector(16), s.id, 0, 0, 100});
	CHECK(is_error(conn->take<protocol::download_data_piece_reply>().error, protocol::errc::data_not_held));
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

// (RDS 10) a data server that is to hold a copy pulls like a member, with a ticket of
// its own right - which the transfer quota of the storage's members does not count
TEST_CASE("data connection serves a replica pull", "[unit]") {
	test_data_context context;
	context.transfer = transfer_quota{1500, 600s};
	auto const data_server = crypto::generate_private_key().id();
	auto const sid = securepath::test::random_octet_vector(16);
	auto const data = make_data(4500);
	auto const& id = data.descriptor.manifest_digest;
	context.hold(sid, data, 5);

	test_connection conn{context};
	REQUIRE(!conn.on_connect(protocol::data_hello{}, data_server));
	REQUIRE(!conn.take<protocol::data_hello_reply>().error);

	// a ticket for somebody else is no good, and the right opens no upload
	conn.handle(protocol::download_data_open{1, context.ticket(sid, data.descriptor, crypto::generate_private_key().id(), data_right::replicate)});
	CHECK(is_error(conn.take<protocol::download_data_open_reply>().error, protocol::errc::invalid_data_ticket));
	conn.handle(protocol::upload_data_manifest{2, context.ticket(sid, data.descriptor, data_server, data_right::replicate), data.manifest});
	CHECK(is_error(conn.take<protocol::upload_data_manifest_reply>().error, protocol::errc::invalid_data_ticket));

	conn.handle(protocol::download_data_open{3, context.ticket(sid, data.descriptor, data_server, data_right::replicate)});
	auto const opened = conn.take<protocol::download_data_open_reply>();
	REQUIRE(!opened.error);
	CHECK(opened.manifest == data.manifest);

	// every chunk, far beyond what the members may move in the window
	for(std::uint64_t chunk_no = 0; chunk_no != data.descriptor.chunk_count(); ++chunk_no) {
		auto const size = static_cast<std::uint32_t>(data.descriptor.chunk_enc_size(chunk_no));
		conn.handle(protocol::download_data_piece{4, sid, id, chunk_no, 0, size});
		auto const reply = conn.take<protocol::download_data_piece_reply>();
		CHECK(!reply.error);
		CHECK(reply.bytes == data.chunks.at(chunk_no));
	}

	// and the members' budget is untouched by it
	test_connection member_conn{context};
	auto const member = crypto::generate_private_key().id();
	REQUIRE(!member_conn.on_connect(protocol::data_hello{}, member));
	REQUIRE(!member_conn.take<protocol::data_hello_reply>().error);
	member_conn.handle(protocol::download_data_open{1, context.ticket(sid, data.descriptor, member, data_right::download)});
	REQUIRE(!member_conn.take<protocol::download_data_open_reply>().error);
	member_conn.handle(protocol::download_data_piece{2, sid, id, 0, 0, 1000});
	CHECK(!member_conn.take<protocol::download_data_piece_reply>().error);
	member_conn.handle(protocol::download_data_piece{3, sid, id, 1, 0, 1000});
	CHECK(is_error(member_conn.take<protocol::download_data_piece_reply>().error, protocol::errc::data_transfer_quota_exceeded));
}

// (review O4/O6) what a connection keeps open is bounded: a transfer nothing moved on for
// the idle limit goes, the least recently used goes when the cap is reached, the staged
// pieces of every upload together stay under a limit, and a chunk that is held already
// is not staged again
TEST_CASE("data connection bounds what a client keeps open", "[unit]") {
	test_data_context context;
	auto const member = crypto::generate_private_key().id();
	auto const sid = securepath::test::random_octet_vector(16);
	data_connection_limits limits;
	limits.max_transfers = 2;
	limits.max_staged_bytes = 2500;
	limits.transfer_idle_limit = 60s;
	test_connection conn{context, limits};
	REQUIRE(!conn.on_connect(protocol::data_hello{}, member));
	conn.replies.clear();

	auto const open = [&](client_data const& data, std::uint32_t cid) {
		conn.handle(protocol::upload_data_manifest{cid, context.ticket(sid, data.descriptor, member), data.manifest});
		return conn.take<protocol::upload_data_manifest_reply>();
	};
	auto const piece = [&](client_data const& data, std::uint64_t chunk_no, std::size_t from, std::size_t to) {
		auto const& chunk = data.chunks.at(chunk_no);
		conn.handle(protocol::upload_data_chunk{9, sid, data.descriptor.manifest_digest, chunk_no, from
			, octet_vector(chunk.begin() + static_cast<std::ptrdiff_t>(from), chunk.begin() + static_cast<std::ptrdiff_t>(to))});
		return conn.take<protocol::upload_data_chunk_reply>();
	};
	auto const staged_files = [&] {
		std::size_t n = 0;
		std::error_code ec;
		for(auto const& e : std::filesystem::recursive_directory_iterator{std::filesystem::path{test_root} / to_hex(sid) / "data" / ".staging", ec}) {
			n += e.is_regular_file() ? 1 : 0;
		}
		return n;
	};

	SECTION("idle transfers go, their staged pieces with them") {
		auto const data = make_data(2500);
		REQUIRE(!open(data, 1).error);
		CHECK(!piece(data, 0, 0, 400).error);
		CHECK(staged_files() == 1);
		context.clock += 61s;
		CHECK(is_error(piece(data, 0, 400, 1016).error, protocol::errc::no_such_upload));
		CHECK(staged_files() == 0);
		// opened again it is fine
		CHECK(!open(data, 2).error);
		CHECK(!piece(data, 0, 0, 1016).error);

		// downloads alike
		context.hold(sid, data, 3);
		conn.handle(protocol::download_data_open{3, context.ticket(sid, data.descriptor, member, data_right::download)});
		REQUIRE(!conn.take<protocol::download_data_open_reply>().error);
		conn.handle(protocol::download_data_piece{4, sid, data.descriptor.manifest_digest, 0, 0, 100});
		CHECK(!conn.take<protocol::download_data_piece_reply>().error);
		context.clock += 61s;
		conn.handle(protocol::download_data_piece{5, sid, data.descriptor.manifest_digest, 0, 0, 100});
		CHECK(is_error(conn.take<protocol::download_data_piece_reply>().error, protocol::errc::data_not_held));
	}

	SECTION("the least recently used goes when the cap is reached") {
		auto const a = make_data(2500);
		auto const b = make_data(2500);
		auto const c = make_data(2500);
		REQUIRE(!open(a, 1).error);
		context.clock += 1s;
		REQUIRE(!open(b, 2).error);
		context.clock += 1s;
		// a moves on, so b is the one nothing happened to for longest
		CHECK(!piece(a, 0, 0, 400).error);
		context.clock += 1s;
		REQUIRE(!open(c, 3).error);
		CHECK(is_error(piece(b, 0, 0, 400).error, protocol::errc::no_such_upload));
		CHECK(!piece(a, 0, 400, 1016).error);
		CHECK(!piece(c, 0, 0, 400).error);
	}

	SECTION("the staged pieces of every upload together stay under the limit") {
		auto const a = make_data(2500);
		auto const b = make_data(2500);
		REQUIRE(!open(a, 1).error);
		REQUIRE(!open(b, 2).error);
		// a chunk on its way takes its whole 1016 octets: two fit, a third would not
		CHECK(!piece(a, 0, 0, 400).error);
		CHECK(!piece(b, 0, 0, 400).error);
		CHECK(is_error(piece(a, 1, 0, 400).error, protocol::errc::invalid_data_chunk));
		CHECK(staged_files() == 2);
		// a chunk that came in whole makes room
		CHECK(!piece(a, 0, 400, 1016).error);
		CHECK(!piece(a, 1, 0, 400).error);
		CHECK(staged_files() == 2);
	}

	SECTION("a chunk that is held is not staged again") {
		auto const data = make_data(2500);
		context.hold(sid, data, 3);
		auto const opened = open(data, 1);
		REQUIRE(!opened.error);
		CHECK(have_bitmap(3, opened.have).complete());
		CHECK(is_error(piece(data, 0, 0, 400).error, protocol::errc::invalid_data_chunk));
		CHECK(staged_files() == 0);
	}
}

}
