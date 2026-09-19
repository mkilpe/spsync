#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/server/server_lib/data_server.hpp>
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

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

std::string const server_root = "data_server_test_root";
std::string const client_db = "data_server_test_client.db";
std::filesystem::path const client_root = "data_server_test_client";

/// a data server on an ephemeral port, a record server key it trusts, one client
struct data_server_fixture {
	data_server_fixture() {
		net.add_client(1);
		net.add_client_keys_for_server();
		net.server_context().public_keys().insert(record_server.public_key());

		data_server_params params;
		params.enabled = true;
		params.data_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0);
		params.storage_root = server_root;
		params.record_servers = {record_server.id().in_hex()};
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
	ticket_source tickets(std::vector<data_endpoint> holders, std::chrono::seconds validity = 600s) {
		return [this, holders = std::move(holders), validity](data_descriptor const& d, data_right right
			, std::move_only_function<void(util::result<data_grant>)> cb) {
			data_ticket ticket{sid, d, net.key_id(0), right, clock_type::now() + validity};
			ticket.sign(record_server);
			cb(util::result<data_grant>{data_grant{std::move(ticket), holders}});
		};
	}

	data_descriptor create_data(std::size_t size) {
		encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
		auto writer = store.create(key, 4096);
		writer.write(securepath::test::random_octet_vector(size));
		return writer.finish().descriptor;
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
		return true;
	}

	bool const cleaned{clean()};
	mutable test::test_context net;
	crypto::private_key record_server{crypto::generate_private_key()};
	protocol::storage_id sid{securepath::test::random_octet_vector(16)};
	std::unique_ptr<data_server> server;
	record_data_store store{database::sqlite::create_sqlite_connection(client_db), client_root};

	mutable std::mutex mutex;
	std::vector<data_id> completed;
};

/// what the uploader reported
struct upload_log {
	data_uploader::done_callback done() {
		return [this](data_id const& id, std::optional<error> err) {
			std::unique_lock lock{mutex};
			finished.emplace_back(id, std::move(err));
			++count;
		};
	}

	data_uploader::progress_callback progress() {
		return [this](data_id const&, std::uint64_t transferred, std::uint64_t) {
			std::unique_lock lock{mutex};
			reports.push_back(transferred);
		};
	}

	std::atomic<std::size_t> count{0};
	std::mutex mutex;
	std::vector<std::pair<data_id, std::optional<error>>> finished;
	std::vector<std::uint64_t> reports;
};

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
}

// chunks of the biggest size the limits allow go through: a chunk travels in pieces, so
// neither the packet deserialiser's cap nor the DER codec's 2 MiB limit for one octet
// string (both found with real chunk sizes in RDS 5) bound what a chunk may be
TEST_CASE("data server takes full size chunks", "[unit]") {
	data_server_fixture f;
	encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
	auto writer = f.store.create(key, max_chunk_size);
	writer.write(securepath::test::random_octet_vector(max_chunk_size + 1000));
	auto const data = writer.finish().descriptor;
	REQUIRE(data.chunk_count() == 2);
	REQUIRE(data.chunk_enc_size(0) > max_chunk_size);
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
	CHECK(log.reports.front() == held);
	CHECK(log.reports.back() == data.enc_size);
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
