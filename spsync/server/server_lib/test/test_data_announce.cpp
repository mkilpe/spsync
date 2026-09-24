#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include "data_server_fixtures.hpp"
#include <spsync/server/server_lib/data_server.hpp>
#include <spsync/server/server_lib/storage_server.hpp>
#include <spsync/transfer/data_downloader.hpp>
#include <spsync/transfer/data_uploader.hpp>
#include <spsync/transfer/net_data_channel.hpp>
#include <spsync/server/server_lib/storage.hpp>
#include <spsync/server/server_lib/ticket_issuer.hpp>
#include <spsync/test/test_block_creator.hpp>
#include <spsync/test/test_context.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <spsync/protocol/error.hpp>
#include <spsync/util/result.hpp>
#include <securepath/util/conversions.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>

#include <atomic>
#include <filesystem>

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

using test::all_in_one;

/// upload a new data of the store to the server's data role, with tickets the server
/// signs for itself
data_descriptor upload_to(all_in_one& server, network::context& client_context, crypto::public_key_id const& client
	, protocol::storage_id const& sid, record_data_store& store, std::size_t size) {
	auto const descriptor = test::store_data(store, size, 4096).result.descriptor;
	REQUIRE(!test::upload(store, client_context, test::signed_tickets(server.key(), {server.endpoint()}, sid, client), descriptor.manifest_digest));
	return descriptor;
}


}

// RD13: what a data role completes reaches the availability table of its own record role
// at once, the peers through the s2s announcement - and a link that comes up later gets
// the whole view, so a client on B is told that A has the data
TEST_CASE("data availability is announced to the peers", "[unit]") {
	std::filesystem::remove_all("test-announce-a");
	std::filesystem::remove_all("test-announce-b");
	std::filesystem::remove_all("test-announce-client");
	std::remove("test-announce-client.db");

	test::test_context tctx;
	tctx.add_client(3);
	tctx.share_client_keys();
	network::enable_pk_handshake(tctx.client_context(0));
	network::enable_pk_handshake(tctx.client_context(1));
	auto const key_a = tctx.key_id(0);
	auto const key_b = tctx.key_id(1);

	all_in_one a{tctx.client_context(0), {.root = "test-announce-a", .port = 42770, .s2s_port = 42780, .peers = {peer_config{"127.0.0.1", 42781, key_b}}}};
	auto b = std::make_unique<all_in_one>(tctx.client_context(1)
		, test::all_in_one_params{.root = "test-announce-b", .port = 42771, .s2s_port = 42781, .peers = {peer_config{"127.0.0.1", 42780, key_a}}});

	record_data_store store{database::sqlite::create_sqlite_connection("test-announce-client.db"), "test-announce-client"};
	auto const sid = securepath::test::random_octet_vector(16);

	// a data completed on A before B is there
	a.start();
	auto const early = upload_to(a, tctx.client_context(2), tctx.key_id(2), sid, store, 30000);
	auto const own = a.records.availability().holdings(sid, early.manifest_digest);
	REQUIRE(own.size() == 1);
	CHECK(own[0] == data_holding{key_a, early.chunk_count(), early.chunk_count(), true});
	CHECK(a.records.availability().load(key_a).stored_bytes == early.enc_size);

	// the link comes up: B learns what A holds
	b->start();
	WAIT_CHECK(b->records.availability().holdings(sid, early.manifest_digest).size() == 1, 10s);
	CHECK(b->records.availability().holdings(sid, early.manifest_digest)[0].holder == key_a);

	// a data completed while the link is up is pushed
	auto const late = upload_to(a, tctx.client_context(2), tctx.key_id(2), sid, store, 50000);
	WAIT_CHECK(b->records.availability().holdings(sid, late.manifest_digest).size() == 1, 10s);
	auto const seen = b->records.availability().holdings(sid, late.manifest_digest);
	REQUIRE(seen.size() == 1);
	CHECK(seen[0] == data_holding{key_a, late.chunk_count(), late.chunk_count(), true});
	WAIT_CHECK(b->records.availability().load(key_a).stored_bytes == early.enc_size + late.enc_size, 5s);
	// A holds nothing of B's
	CHECK(a.records.availability().load(key_b) == holder_load{});

	// the table is transient: a restarted A reads what its data role holds again
	b->close();
	b.reset();
	a.close();
	all_in_one restarted{tctx.client_context(0), {.root = "test-announce-a", .port = 42770, .s2s_port = 42780}};
	restarted.start();
	CHECK(restarted.records.availability().holdings(sid, early.manifest_digest).size() == 1);
	CHECK(restarted.records.availability().holdings(sid, late.manifest_digest).size() == 1);
	restarted.close();
}

// RD12, the other deployment shape: a record server without a data role and a data server
// without a chain. The data server dials the record server's s2s listener - accepted for
// announcements only - learns the key its tickets are signed with from that link, and
// tells what it holds; the record server issues the tickets and orders the holders
TEST_CASE("separate data server", "[unit]") {
	std::filesystem::remove_all("test-separate-records");
	std::filesystem::remove_all("test-separate-data");
	std::filesystem::remove_all("test-announce-client");
	std::remove("test-announce-client.db");

	test::test_context tctx;
	tctx.add_client(4);
	tctx.share_client_keys();
	auto& record_context = tctx.client_context(0);
	auto& data_context = tctx.client_context(1);
	network::enable_pk_handshake(record_context);
	network::enable_pk_handshake(data_context);
	auto const record_key = tctx.key_id(0);
	auto const data_key = tctx.key_id(1);

	// the data server does not know the record server's key before the link told it
	data_context.public_keys().remove(record_key);
	REQUIRE(!data_context.public_keys().find(record_key));

	data_server_params dparams;
	dparams.enabled = true;
	dparams.storage_root = "test-separate-data";
	dparams.data_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 42792);
	dparams.record_servers = {peer_config{"127.0.0.1", 42791, record_key}};
	data_server data{data_context, dparams};

	storage_server_params rparams;
	rparams.storage_root = "test-separate-records";
	rparams.storage_server_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 42790);
	rparams.s2s_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 42791);
	data_endpoint const endpoint{"127.0.0.1", 42792, data_key, {}, {}};
	rparams.data_servers = {endpoint};
	storage_server records{record_context, rparams};

	// the data server first: its link finds nobody, and comes back
	data.start();
	records.start();
	REQUIRE(records.s2s_local_endpoint().has_value());
	WAIT_REQUIRE(data.connected_record_servers() == std::vector<crypto::public_key_id>{record_key}, 15s);
	CHECK(data_context.public_keys().find(record_key));
	// no replication peer: the record server talks records to nobody
	CHECK(records.connected_peers().size() <= 1);

	// a storage with a committed data change, as a client's commit leaves it
	auto const sid = securepath::test::random_octet_vector(16);
	auto storage = records.open_storage(sid, storage_modes{sync_mode::allow_all, auth_mode::only_tag});
	record_data_store store{database::sqlite::create_sqlite_connection("test-announce-client.db"), "test-announce-client"};
	encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
	auto writer = store.create(key, chunk_size_range.lowest);
	auto const plain = securepath::test::random_octet_vector(700000);
	writer.write(plain);
	auto const made = writer.finish();
	test::test_block_creator creator;
	REQUIRE(storage->commit_block(creator.test_user_change()).block);
	REQUIRE(storage->commit_block(creator.test_data_change_with_data(made.descriptor)).block);

	// the record server's part of a transfer, as its connection handler does it
	auto const tickets = [&](std::size_t client) {
		return ticket_source{[&, client](data_descriptor const& d, data_right right, std::move_only_function<void(util::result<data_grant>)> cb) {
			ticket_issuer issuer{{endpoint}, records.availability(), 600s};
			auto issued = issuer.issue(sid, storage->committed_data(d.manifest_digest), tctx.key_id(client)
				, static_cast<std::uint32_t>(right), record_context.private_data().my_private_key(), clock_type::now());
			if(issued) {
				cb(util::result<data_grant>{data_grant{std::move(issued->ticket), std::move(issued->holders)}});
			} else {
				cb(util::result<data_grant>{issued.get_error()});
			}
		}};
	};

	// client 2 uploads with a ticket of the record server, to the data server
	{
		net_data_channel channel{tctx.client_context(2), tickets(2)};
		std::atomic<int> done{0};
		std::atomic<bool> failed{false};
		data_uploader uploader{store, channel, data_upload_config{}, [&](data_id const&, std::optional<error> err) {
			failed = err.has_value();
			++done;
		}};
		REQUIRE(uploader.enqueue(made.descriptor.manifest_digest));
		WAIT_REQUIRE(done == 1, 30s);
		REQUIRE(!failed);
	}

	// the data server told the record server
	WAIT_CHECK(records.availability().holdings(sid, made.descriptor.manifest_digest).size() == 1, 10s);
	auto const holdings = records.availability().holdings(sid, made.descriptor.manifest_digest);
	REQUIRE(holdings.size() == 1);
	CHECK(holdings[0] == data_holding{data_key, made.descriptor.chunk_count(), made.descriptor.chunk_count(), true});
	CHECK(records.availability().load(data_key).stored_bytes == made.descriptor.enc_size);

	// client 3 downloads
	std::filesystem::remove_all("test-separate-reader");
	std::remove("test-separate-reader.db");
	record_data_store reader{database::sqlite::create_sqlite_connection("test-separate-reader.db"), "test-separate-reader"};
	auto handle = reader.open({key}, made.descriptor, made.header);
	REQUIRE(handle);
	{
		net_data_channel channel{tctx.client_context(3), tickets(3)};
		std::atomic<int> done{0};
		std::atomic<bool> failed{false};
		data_downloader downloader{reader, channel, data_download_config{}, [&](data_id const&, std::optional<error> err) {
			failed = err.has_value();
			++done;
		}};
		REQUIRE(downloader.enqueue(made.descriptor.manifest_digest));
		WAIT_REQUIRE(done == 1, 30s);
		CHECK(!failed);
	}
	octet_vector read_back(plain.size());
	CHECK(handle->read(0, read_back.data(), read_back.size()) == plain.size());
	CHECK(read_back == plain);

	// a restarted record server gets the whole view again when the link comes back
	records.close();
	storage.reset();
	storage_server restarted{record_context, rparams};
	restarted.start();
	WAIT_CHECK(restarted.availability().holdings(sid, made.descriptor.manifest_digest).size() == 1, 30s);

	// (RDS 9) the record naming the data is rolled back: the record server forgets the
	// holder, refuses tickets, and tells the data server over its link to drop the chunks
	auto reopened = restarted.open_storage(sid);
	REQUIRE(reopened);
	REQUIRE(reopened->committed_data(made.descriptor.manifest_digest));
	CHECK(data.find(sid, made.descriptor.manifest_digest));
	CHECK(reopened->truncate_from(sequence_number{2}).size() == 1);
	CHECK(!reopened->committed_data(made.descriptor.manifest_digest));
	CHECK(restarted.availability().holdings(sid, made.descriptor.manifest_digest).empty());
	WAIT_CHECK(!data.find(sid, made.descriptor.manifest_digest), 10s);
	CHECK(!std::filesystem::exists(std::filesystem::path{"test-separate-data"} / to_hex(sid) / "data" / to_hex(made.descriptor.manifest_digest)));
	CHECK(data.stored_bytes() == 0);

	reopened.reset();
	restarted.close();
	data.close();
}

// (RDS 9) the same in the all-in-one shape: the record role tells its own data role
// directly; data a record that stays still names is kept
TEST_CASE("all in one server releases the data of removed records", "[unit]") {
	std::filesystem::remove_all("test-release-a");
	std::filesystem::remove_all("test-announce-client");
	std::remove("test-announce-client.db");

	test::test_context tctx;
	tctx.add_client(2);
	tctx.share_client_keys();
	network::enable_pk_handshake(tctx.client_context(0));
	all_in_one server{tctx.client_context(0), {.root = "test-release-a", .port = 42772, .s2s_port = 42782}};
	server.start();

	record_data_store store{database::sqlite::create_sqlite_connection("test-announce-client.db"), "test-announce-client"};
	auto const sid = securepath::test::random_octet_vector(16);
	auto const kept = upload_to(server, tctx.client_context(1), tctx.key_id(1), sid, store, 30000);
	auto const dead = upload_to(server, tctx.client_context(1), tctx.key_id(1), sid, store, 50000);
	REQUIRE(server.records.availability().holdings(sid, dead.manifest_digest).size() == 1);

	// the chain that names them. The descriptors of this test have small chunks, which
	// the chain would refuse: the records name data of the same ids with valid sizes
	auto const named = [](data_descriptor const& d) {
		return data_descriptor{3 * 1024 * 1024 + 48, 1024 * 1024, d.manifest_digest};
	};
	auto storage = server.records.open_storage(sid, storage_modes{sync_mode::allow_all, auth_mode::only_tag});
	test::test_block_creator creator;
	REQUIRE(storage->commit_block(creator.test_user_change()).block);
	auto const before = server.data.stored_bytes();
	CHECK(before == kept.enc_size + dead.enc_size);

	SECTION("a rollback") {
		REQUIRE(storage->commit_block(creator.test_data_change_with_data(named(kept))).block);
		REQUIRE(storage->commit_block(creator.test_data_change_with_data(named(dead))).block);
		CHECK(storage->truncate_from(sequence_number{3}).size() == 1);
		CHECK(check_result_error(storage->committed_data(dead.manifest_digest), protocol::errc::unknown_data));
	}

	SECTION("a cut and the retention policy") {
		// two versions of one object: the storage keeps the data of the newest one only
		REQUIRE(storage->modes().limits.kept_data_versions == 1);
		auto const oid = util::create_object_id();
		auto const v1 = creator.test_versions({{oid, {}, named(dead)}});
		REQUIRE(storage->commit_block(v1).block);
		REQUIRE(storage->commit_block(creator.test_versions({{oid, v1.tag(), named(kept)}})).block);
		auto const segment = creator.test_segment(plain_segment_data{sequence_number{1}, sequence_number{4}, creator.created_tags});
		REQUIRE(storage->commit_block(segment).block);

		// both records stay, the data of the first goes: no ticket for it any more
		CHECK(storage->cut_history(segment.tag()).size() == 1);
		CHECK(storage->get_records(v1.sequence(), v1.sequence()).size() == 1);
		CHECK(check_result_error(storage->committed_data(dead.manifest_digest), protocol::errc::data_pruned));
	}

	CHECK(!server.data.find(sid, dead.manifest_digest));
	CHECK(server.records.availability().holdings(sid, dead.manifest_digest).empty());
	CHECK(server.data.stored_bytes() == kept.enc_size);
	// the other one is untouched
	auto const row = server.data.find(sid, kept.manifest_digest);
	REQUIRE(row);
	CHECK(row->state == record_data_state::in_sync);
	CHECK(server.records.availability().holdings(sid, kept.manifest_digest).size() == 1);
	CHECK(storage->committed_data(kept.manifest_digest));

	storage.reset();
	server.close();
}

}
