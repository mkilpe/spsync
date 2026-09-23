#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include "data_server_fixtures.hpp"
#include <spsync/server/server_lib/data_server.hpp>
#include <spsync/comm/data_downloader.hpp>
#include <spsync/comm/data_uploader.hpp>
#include <spsync/comm/net_data_channel.hpp>
#include <spsync/protocol/data_protocol.hpp>
#include <spsync/protocol/error.hpp>
#include <spsync/test/test_context.hpp>
#include <spsync/test/test_server_runner.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <atomic>
#include <filesystem>
#include <future>
#include <mutex>
#include <thread>

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

std::string const server_root = "data_server_test_root";
std::string const client_db = "data_server_test_client.db";
std::filesystem::path const client_root = "data_server_test_client";
std::string const reader_db = "data_server_test_reader.db";
std::filesystem::path const reader_root = "data_server_test_reader";

/// a data server on an ephemeral port, a record server key it trusts, one client
struct data_server_fixture {
	explicit data_server_fixture(transfer_quota transfer = {}) {
		net.add_client(2);
		net.add_client_keys_for_server();
		net.server_context().public_keys().insert(record_server.public_key());

		data_server_params params;
		params.enabled = true;
		params.data_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0);
		params.storage_root = server_root;
		// trusted for its tickets; there is no record server to keep a link to here
		params.record_servers = {peer_config{"", 0, record_server.id()}};
		params.transfer = transfer;
		server = std::make_unique<data_server>(net.server_context(), params);
		server->set_complete_handler([this](protocol::storage_id const&, data_id const& id) {
			std::unique_lock lock{mutex};
			completed.push_back(id);
		});
		server->start();
	}

	data_endpoint endpoint() const {
		return data_endpoint{"127.0.0.1", server->local_endpoint()->port()
			, crypto::my_private_key(net.server_context().private_data()).id(), {}};
	}

	/// the record server's part: a ticket for the client, the given holders
	ticket_source tickets(std::vector<data_endpoint> holders, std::chrono::seconds validity = 600s, std::size_t client = 0) {
		return test::signed_tickets(record_server, std::move(holders), sid, net.key_id(client), validity);
	}

	data_descriptor create_data(std::size_t size) {
		return create_full(size).descriptor;
	}

	/// both descriptor halves; the plaintext is kept for a reader to compare with
	encrypted_data_result create_full(std::size_t size) {
		auto made = test::store_data(store, size, 4096, group_key);
		plain = std::move(made.plain);
		return std::move(made.result);
	}

	/// the author (client 0) puts the data on the server
	void upload(data_descriptor const& d) {
		net_data_channel channel{net.client_context(0), tickets({endpoint()})};
		std::atomic<int> done{0};
		std::atomic<bool> failed{false};
		data_uploader uploader{store, channel, data_upload_config{}, [&](data_id const&, std::optional<error> err) {
			failed = err.has_value();
			++done;
		}};
		REQUIRE(uploader.enqueue(d.manifest_digest));
		WAIT_REQUIRE(done == 1, 30s);
		REQUIRE(!failed);
	}

	std::size_t completed_count() const {
		std::unique_lock lock{mutex};
		return completed.size();
	}

	/// what an earlier run left behind goes before anything opens it
	static bool clean() {
		std::filesystem::remove_all(server_root);
		std::filesystem::remove_all(client_root);
		std::remove(client_db.c_str());
		std::filesystem::remove_all(reader_root);
		std::remove(reader_db.c_str());
		return true;
	}

	bool const cleaned{clean()};
	mutable test::test_context net;
	crypto::private_key record_server{crypto::generate_private_key()};
	protocol::storage_id sid{securepath::test::random_octet_vector(16)};
	std::unique_ptr<data_server> server;
	encryption_key group_key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
	octet_vector plain;
	record_data_store store{database::sqlite::create_sqlite_connection(client_db), client_root};
	/// the store of the second client, the reader
	record_data_store reader_store{database::sqlite::create_sqlite_connection(reader_db), reader_root};

	mutable std::mutex mutex;
	std::vector<data_id> completed;
};

using upload_log = test::transfer_log;

}

// RDS 4: the client's data channel and the data listener, over the wire
TEST_CASE("data server upload end to end", "[unit]") {
	data_server_fixture f;
	auto const big = f.create_data(300000);
	auto const small = f.create_data(100);

	net_data_channel channel{f.net.client_context(0), f.tickets({f.endpoint()})};
	upload_log log;
	data_uploader uploader{f.store, channel, data_upload_config{}, log.done(), log.progress()};
	CHECK(uploader.enqueue(big.manifest_digest));
	CHECK(uploader.enqueue(small.manifest_digest));
	WAIT_CHECK(log.count == 2, 20s);
	REQUIRE(log.finished.size() == 2);
	for(auto const& done : log.finished) {
		CHECK(!done.second);
	}

	// the server holds what the client holds, verified chunk by chunk on the way in
	auto server_store = f.server->open_store(f.sid);
	for(auto const& d : {big, small}) {
		auto const row = server_store->find(d.manifest_digest);
		REQUIRE(row);
		CHECK(row->descriptor == d);
		CHECK(row->state == record_data_state::in_sync);
		bool same = true;
		for(std::uint64_t no = 0; no != d.chunk_count(); ++no) {
			same = same && server_store->read_chunk(d.manifest_digest, no) == f.store.read_chunk(d.manifest_digest, no);
		}
		CHECK(same);
	}
	CHECK(std::filesystem::exists(std::filesystem::path{server_root} / to_hex(f.sid) / "data.db"));
	CHECK(server_store->used_bytes() == big.enc_size + small.enc_size);
	WAIT_CHECK(f.completed_count() == 2, 2s);

	// again: the holder has everything, nothing moves
	CHECK(uploader.enqueue(big.manifest_digest));
	WAIT_CHECK(log.count == 3, 10s);
	CHECK(!log.finished.back().second);
	CHECK(f.completed_count() == 2);

	// (RDS 10) everything held as the whole view a link gets: bracketed, so the receiver
	// replaces what it knew of this holder and knows when it has heard all of it
	auto const holder = crypto::generate_private_key().id();
	auto const view = f.server->announcements(holder);
	REQUIRE(view.size() == 1);
	CHECK(view[0].view_begin);
	CHECK(view[0].view_end);
	CHECK(view[0].entries.size() == 2);
	// the news of one data is not a view
	auto const news = f.server->announcement(holder, f.sid, big.manifest_digest);
	REQUIRE(news);
	CHECK(!news->view_begin);
	CHECK(!news->view_end);
}

// (review 2026-09-21) closing the channel ends what is out - it used to fail the pending
// opens as "this holder is down", which is what moves on to the next holder: a close made
// new connections, and the next data server got a manifest nobody waited for
TEST_CASE("data channel close does not fail over", "[unit]") {
	data_server_fixture f;
	auto const data = f.create_data(3000);

	// a holder that takes the connection and never says a word: the open stays out
	asio::ip::tcp::acceptor silent{f.net.client_context(0).io_context(), asio::ip::tcp::endpoint{asio::ip::address_v4::loopback(), 0}};
	std::vector<asio::ip::tcp::socket> taken;
	std::function<void()> accept = [&] {
		silent.async_accept([&](std::error_code const& ec, asio::ip::tcp::socket socket) {
			if(!ec) {
				taken.push_back(std::move(socket));
				accept();
			}
		});
	};
	accept();
	data_endpoint const mute{"127.0.0.1", silent.local_endpoint().port(), f.endpoint().key, {}};

	net_data_channel channel{f.net.client_context(0), f.tickets({mute, f.endpoint()})};
	upload_log log;
	data_uploader uploader{f.store, channel, data_upload_config{}, log.done(), log.progress()};
	REQUIRE(uploader.enqueue(data.manifest_digest));
	std::this_thread::sleep_for(300ms);
	channel.close();

	WAIT_REQUIRE(log.count == 1, 10s);
	CHECK(log.finished.back().second.has_value());
	// the real server, second in the list, never heard of the data
	std::this_thread::sleep_for(500ms);
	CHECK(!f.server->find(f.sid, data.manifest_digest));
	silent.close();
}

// chunks of the biggest size the limits allow go through: a chunk travels in pieces, so
// neither the packet deserialiser's cap nor the DER codec's 2 MiB limit for one octet
// string (both found with real chunk sizes in RDS 5) bound what a chunk may be
TEST_CASE("data server takes full size chunks", "[unit]") {
	data_server_fixture f;
	encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
	auto writer = f.store.create(key, chunk_size_range.highest);
	writer.write(securepath::test::random_octet_vector(chunk_size_range.highest + 1000));
	auto const data = writer.finish().descriptor;
	REQUIRE(data.chunk_count() == 2);
	REQUIRE(data.chunk_enc_size(0) > chunk_size_range.highest);
	REQUIRE(data.chunk_enc_size(0) > protocol::max_data_piece_size);

	net_data_channel channel{f.net.client_context(0), f.tickets({f.endpoint()})};
	upload_log log;
	data_uploader uploader{f.store, channel, data_upload_config{}, log.done()};
	CHECK(uploader.enqueue(data.manifest_digest));
	WAIT_CHECK(log.count == 1, 60s);
	REQUIRE(log.finished.size() == 1);
	CHECK(!log.finished[0].second);
	auto const server_store = f.server->open_store(f.sid);
	CHECK(server_store->find(data.manifest_digest)->state == record_data_state::in_sync);
	CHECK(server_store->read_chunk(data.manifest_digest, 0) == f.store.read_chunk(data.manifest_digest, 0));
	CHECK(server_store->read_chunk(data.manifest_digest, 1) == f.store.read_chunk(data.manifest_digest, 1));
}

// RD4: an interrupted upload resumes from what the server holds
TEST_CASE("data server upload resume", "[unit]") {
	data_server_fixture f;
	auto const data = f.create_data(200000);
	auto const& id = data.manifest_digest;
	auto const manifest = f.store.manifest(id).value();
	std::uint64_t const first_part = 10;

	{
		// the first try gets ten chunks over, then the connection goes
		net_data_channel channel{f.net.client_context(0), f.tickets({f.endpoint()})};
		std::promise<bool> opened;
		channel.open_upload(data, manifest, [&](util::result<have_bitmap> have) { opened.set_value(have && have->count() == 0); });
		REQUIRE(opened.get_future().get());

		std::atomic<std::uint64_t> acked{0};
		for(std::uint64_t no = 0; no != first_part; ++no) {
			// a chunk of 4 KiB fits one piece
			channel.send_piece(id, no, 0, f.store.read_chunk(id, no).value(), [&](std::optional<error> err) { acked += err ? 0 : 1; });
		}
		WAIT_CHECK(acked == first_part, 10s);
		channel.close();
	}
	CHECK(f.server->open_store(f.sid)->find(id)->have.count() == first_part);

	net_data_channel channel{f.net.client_context(0), f.tickets({f.endpoint()})};
	upload_log log;
	data_uploader uploader{f.store, channel, data_upload_config{}, log.done(), log.progress()};
	CHECK(uploader.enqueue(id));
	WAIT_CHECK(log.count == 1, 20s);
	REQUIRE(log.finished.size() == 1);
	CHECK(!log.finished[0].second);

	// progress started from what the server already had
	std::uint64_t held = 0;
	for(std::uint64_t no = 0; no != first_part; ++no) {
		held += data.chunk_enc_size(no);
	}
	REQUIRE(!log.reports.empty());
	CHECK(log.reports.front().transferred == held);
	CHECK(log.reports.back().transferred == data.enc_size);
	CHECK(f.server->open_store(f.sid)->find(id)->state == record_data_state::in_sync);
	WAIT_CHECK(f.completed_count() == 1, 2s);
}

// RD13: a holder that is down is the next entry; RD12: the holder proves to be the one the grant names
TEST_CASE("data server holders", "[unit]") {
	data_server_fixture f;
	auto const data = f.create_data(30000);
	upload_log log;

	SECTION("failover down the list") {
		data_endpoint down = f.endpoint();
		down.port = 1;
		net_data_channel channel{f.net.client_context(0), f.tickets({down, f.endpoint()}), 5s};
		data_uploader uploader{f.store, channel, data_upload_config{}, log.done()};
		CHECK(uploader.enqueue(data.manifest_digest));
		WAIT_CHECK(log.count == 1, 30s);
		REQUIRE(log.finished.size() == 1);
		CHECK(!log.finished[0].second);
		CHECK(f.server->open_store(f.sid)->find(data.manifest_digest)->state == record_data_state::in_sync);
	}

	SECTION("nobody reachable") {
		data_endpoint down = f.endpoint();
		down.port = 1;
		net_data_channel channel{f.net.client_context(0), f.tickets({down}), 5s};
		data_uploader uploader{f.store, channel, data_upload_config{}, log.done()};
		CHECK(uploader.enqueue(data.manifest_digest));
		WAIT_CHECK(log.count == 1, 30s);
		REQUIRE(log.finished.size() == 1);
		CHECK(log.finished[0].second);
	}

	SECTION("no holder named") {
		net_data_channel channel{f.net.client_context(0), f.tickets({})};
		data_uploader uploader{f.store, channel, data_upload_config{}, log.done()};
		CHECK(uploader.enqueue(data.manifest_digest));
		WAIT_CHECK(log.count == 1, 10s);
		REQUIRE(log.finished.size() == 1);
		REQUIRE(log.finished[0].second);
		CHECK(log.finished[0].second->code() == make_error_code(securepath::errc::no_such_data));
	}

	SECTION("a server with another key than the grant names") {
		data_endpoint impostor = f.endpoint();
		impostor.key = crypto::generate_private_key().id();
		net_data_channel channel{f.net.client_context(0), f.tickets({impostor})};
		data_uploader uploader{f.store, channel, data_upload_config{}, log.done()};
		CHECK(uploader.enqueue(data.manifest_digest));
		WAIT_CHECK(log.count == 1, 10s);
		REQUIRE(log.finished.size() == 1);
		CHECK(log.finished[0].second);
		CHECK(!f.server->open_store(f.sid)->find(data.manifest_digest));
	}
}

// the server's refusals arrive as what they are
TEST_CASE("data server refusals over the wire", "[unit]") {
	data_server_fixture f;
	auto const data = f.create_data(30000);
	upload_log log;

	SECTION("expired ticket") {
		net_data_channel channel{f.net.client_context(0), f.tickets({f.endpoint()}, -10s)};
		data_uploader uploader{f.store, channel, data_upload_config{}, log.done()};
		CHECK(uploader.enqueue(data.manifest_digest));
		WAIT_CHECK(log.count == 1, 10s);
		REQUIRE(log.finished.size() == 1);
		REQUIRE(log.finished[0].second);
		CHECK(log.finished[0].second->code() == make_error_code(protocol::errc::data_ticket_expired));
	}

	SECTION("a ticket of a record server the data server does not know") {
		auto const stranger = crypto::generate_private_key();
		ticket_source source = [&](data_descriptor const& d, data_right right, std::move_only_function<void(util::result<data_grant>)> cb) {
			data_ticket ticket{f.sid, d, f.net.key_id(0), right, clock_type::now() + 10min};
			ticket.sign(stranger);
			cb(util::result<data_grant>{data_grant{std::move(ticket), {f.endpoint()}}});
		};
		net_data_channel channel{f.net.client_context(0), source};
		data_uploader uploader{f.store, channel, data_upload_config{}, log.done()};
		CHECK(uploader.enqueue(data.manifest_digest));
		WAIT_CHECK(log.count == 1, 10s);
		REQUIRE(log.finished.size() == 1);
		REQUIRE(log.finished[0].second);
		CHECK(log.finished[0].second->code() == make_error_code(protocol::errc::invalid_data_ticket));
	}

	SECTION("the record server refuses the ticket") {
		ticket_source source = [](data_descriptor const&, data_right, std::move_only_function<void(util::result<data_grant>)> cb) {
			cb(util::result<data_grant>{make_error(protocol::errc::no_such_storage)});
		};
		net_data_channel channel{f.net.client_context(0), source};
		data_uploader uploader{f.store, channel, data_upload_config{}, log.done()};
		CHECK(uploader.enqueue(data.manifest_digest));
		WAIT_CHECK(log.count == 1, 10s);
		REQUIRE(log.finished.size() == 1);
		REQUIRE(log.finished[0].second);
		CHECK(log.finished[0].second->code() == make_error_code(protocol::errc::no_such_storage));
	}

	SECTION("a chunk without an opened upload") {
		net_data_channel channel{f.net.client_context(0), f.tickets({f.endpoint()})};
		std::promise<std::optional<error>> answer;
		channel.send_piece(data.manifest_digest, 0, 0, f.store.read_chunk(data.manifest_digest, 0).value()
			, [&](std::optional<error> err) { answer.set_value(std::move(err)); });
		auto const err = answer.get_future().get();
		REQUIRE(err);
		CHECK(err->code() == make_error_code(protocol::errc::no_such_upload));
	}
}

// incomplete uploads of a server that was restarted expire as well
TEST_CASE("data server expires incomplete uploads", "[unit]") {
	data_server_fixture f;
	auto const data = f.create_data(30000);
	auto const& id = data.manifest_digest;
	{
		net_data_channel channel{f.net.client_context(0), f.tickets({f.endpoint()})};
		std::promise<bool> opened;
		channel.open_upload(data, f.store.manifest(id).value(), [&](util::result<have_bitmap> have) { opened.set_value(static_cast<bool>(have)); });
		REQUIRE(opened.get_future().get());
	}
	CHECK(f.server->open_store(f.sid)->find(id));
	// nothing is old enough with the default day
	CHECK(f.server->expire_incomplete() == 0);
	f.server->close();
	f.server.reset();

	data_server_params params;
	params.enabled = true;
	params.data_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0);
	params.storage_root = server_root;
	params.incomplete_upload_expiry = -1h;
	data_server restarted{f.net.server_context(), params};
	// the expiry runs at start over the stores found on disk
	restarted.start();
	CHECK(!restarted.open_store(f.sid)->find(id));
	CHECK(restarted.open_store(f.sid)->used_bytes() == 0);
}

namespace {

using download_log = test::transfer_log;
using test::read_all;

}

// RDS 6: the first whole way of a data - the author uploads, another member downloads
// with its own ticket over its own connection, verifies every chunk and reads the plaintext
TEST_CASE("data server download end to end", "[unit]") {
	data_server_fixture f;
	auto const data = f.create_full(700000);
	auto const& id = data.descriptor.manifest_digest;
	f.upload(data.descriptor);

	// the reader's record named the data: known, nothing held
	auto handle = f.reader_store.open({f.group_key}, data.descriptor, data.header);
	REQUIRE(handle);
	CHECK(handle->state() == record_data_state::deferred);

	net_data_channel channel{f.net.client_context(1), f.tickets({f.endpoint()}, 600s, 1)};
	download_log log;
	data_downloader downloader{f.reader_store, channel, data_download_config{}, log.done()};
	CHECK(downloader.enqueue(id));
	WAIT_CHECK(log.count == 1, 30s);
	REQUIRE(log.finished.size() == 1);
	CHECK(!log.finished[0].second);
	CHECK(handle->state() == record_data_state::in_sync);
	CHECK(read_all(*handle) == f.plain);
	CHECK(f.reader_store.manifest(id) == data.manifest);
}

// RD13: a holder that is down is the next entry, for downloads too
TEST_CASE("data server download failover", "[unit]") {
	data_server_fixture f;
	auto const data = f.create_full(60000);
	f.upload(data.descriptor);
	auto handle = f.reader_store.open({f.group_key}, data.descriptor, data.header);
	REQUIRE(handle);

	data_endpoint down = f.endpoint();
	down.port = 1;
	net_data_channel channel{f.net.client_context(1), f.tickets({down, f.endpoint()}, 600s, 1), 5s};
	download_log log;
	data_downloader downloader{f.reader_store, channel, data_download_config{}, log.done()};
	CHECK(downloader.enqueue(data.descriptor.manifest_digest));
	WAIT_CHECK(log.count == 1, 30s);
	REQUIRE(log.finished.size() == 1);
	CHECK(!log.finished[0].second);
	CHECK(read_all(*handle) == f.plain);
}

// the server's refusals of a download arrive as what they are
TEST_CASE("data server download refusals", "[unit]") {
	data_server_fixture f;
	auto const data = f.create_full(60000);
	auto handle = f.reader_store.open({f.group_key}, data.descriptor, data.header);
	REQUIRE(handle);
	download_log log;

	SECTION("a data nobody uploaded") {
		net_data_channel channel{f.net.client_context(1), f.tickets({f.endpoint()}, 600s, 1)};
		data_downloader downloader{f.reader_store, channel, data_download_config{}, log.done()};
		CHECK(downloader.enqueue(data.descriptor.manifest_digest));
		WAIT_CHECK(log.count == 1, 10s);
		REQUIRE(log.finished.size() == 1);
		REQUIRE(log.finished[0].second);
		CHECK(log.finished[0].second->code() == make_error_code(protocol::errc::data_not_held));
		CHECK(handle->state() == record_data_state::deferred);
	}

	SECTION("somebody else's ticket") {
		f.upload(data.descriptor);
		// issued to client 0, presented by client 1
		net_data_channel channel{f.net.client_context(1), f.tickets({f.endpoint()}, 600s, 0)};
		data_downloader downloader{f.reader_store, channel, data_download_config{}, log.done()};
		CHECK(downloader.enqueue(data.descriptor.manifest_digest));
		WAIT_CHECK(log.count == 1, 10s);
		REQUIRE(log.finished.size() == 1);
		REQUIRE(log.finished[0].second);
		CHECK(log.finished[0].second->code() == make_error_code(protocol::errc::invalid_data_ticket));
		CHECK(handle->available_size() == 0);
	}
}

// RD10: a fetch that runs into the transfer quota keeps what it got and goes on in the next window
TEST_CASE("data server transfer quota window", "[unit]") {
	// windows of two seconds that serve less than half of the data each: the windows are
	// fixed to the clock, so a download may straddle two of them whenever it starts - it
	// still cannot finish without being refused once
	data_server_fixture f{transfer_quota{25000, 2s}};
	auto const data = f.create_full(60000);
	auto const& id = data.descriptor.manifest_digest;
	f.upload(data.descriptor);
	auto handle = f.reader_store.open({f.group_key}, data.descriptor, data.header);
	REQUIRE(handle);

	net_data_channel channel{f.net.client_context(1), f.tickets({f.endpoint()}, 600s, 1)};
	download_log log;
	data_downloader downloader{f.reader_store, channel, data_download_config{2, 2, 4096}, log.done()};

	std::size_t tries = 0;
	bool complete = false;
	std::uint64_t held_after_first = 0;
	while(!complete && tries != 10) {
		CHECK(downloader.enqueue(id));
		++tries;
		WAIT_REQUIRE(log.count == tries, 30s);
		complete = !log.finished.back().second.has_value();
		if(!complete) {
			CHECK(log.finished.back().second->code() == make_error_code(protocol::errc::data_transfer_quota_exceeded));
			held_after_first = held_after_first == 0 ? f.reader_store.find(id)->have.count() : held_after_first;
			// the next window
			std::this_thread::sleep_for(2s);
		}
	}
	CHECK(complete);
	// it took more than one window, and the first one left whole chunks behind
	CHECK(tries >= 2);
	CHECK(held_after_first > 0);
	CHECK(held_after_first < data.descriptor.chunk_count());
	CHECK(read_all(*handle) == f.plain);
}

// RD12: the all-in-one deployment - the same server has the record and the data role and
// accepts the tickets it signs itself; without the option no data listener runs
TEST_CASE("spsync server data role", "[unit]") {
	std::filesystem::remove_all("data_role_test_root");
	std::filesystem::remove_all(client_root);
	std::remove(client_db.c_str());
	test::test_context net;
	net.add_client(1);
	net.add_client_keys_for_server();

	SECTION("off by default") {
		test::test_server server{net.server_context()};
		server.run();
		std::this_thread::sleep_for(1s);
		CHECK(!server.data().local_endpoint());
	}

	SECTION("enabled") {
		spsync_server_params params;
		params.storage_params.storage_root = "data_role_test_root";
		params.data_params.enabled = true;
		params.data_params.storage_root = "data_role_test_root";
		params.data_params.data_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0);
		test::test_server server{net.server_context(), params};
		server.run();
		WAIT_REQUIRE(server.data().local_endpoint().has_value(), 10s);

		auto const server_key = crypto::my_private_key(net.server_context().private_data());
		auto const sid = securepath::test::random_octet_vector(16);
		data_endpoint const endpoint{"127.0.0.1", server.data().local_endpoint()->port(), server_key.id(), {}};
		ticket_source source = [&](data_descriptor const& d, data_right right, std::move_only_function<void(util::result<data_grant>)> cb) {
			data_ticket ticket{sid, d, net.key_id(0), right, clock_type::now() + 10min};
			ticket.sign(server_key);
			cb(util::result<data_grant>{data_grant{std::move(ticket), {endpoint}}});
		};

		record_data_store store{database::sqlite::create_sqlite_connection(client_db), client_root};
		encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
		auto writer = store.create(key, 4096);
		writer.write(securepath::test::random_octet_vector(50000));
		auto const data = writer.finish().descriptor;

		net_data_channel channel{net.client_context(0), source};
		upload_log log;
		data_uploader uploader{store, channel, data_upload_config{}, log.done()};
		CHECK(uploader.enqueue(data.manifest_digest));
		WAIT_CHECK(log.count == 1, 20s);
		REQUIRE(log.finished.size() == 1);
		CHECK(!log.finished[0].second);
		CHECK(server.data().open_store(sid)->find(data.manifest_digest)->state == record_data_state::in_sync);
		// the data of a storage lives next to its records
		CHECK(std::filesystem::exists(std::filesystem::path{"data_role_test_root"} / to_hex(sid) / "data" / to_hex(data.manifest_digest)));
	}
}

}
