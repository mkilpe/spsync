// SPDX-License-Identifier: MIT

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

/// the slot of a test server of this file (test_ports.hpp)
int announce_slot(int i) {
	return test::announce_test_slots + i;
}

/// upload a new data of the store to the server's data role, with tickets the server
/// signs for itself
data_descriptor upload_to(all_in_one& server, network::context& client_context, crypto::public_key_id const& client
	, protocol::storage_id const& sid, record_data_store& store, std::size_t size) {
	auto const descriptor = test::store_data(store, size, 4096).result.descriptor;
	REQUIRE(!test::upload(store, client_context, test::signed_tickets(server.key(), {server.endpoint()}, sid, client), descriptor.manifest_digest));
	return descriptor;
}

/// two all-in-one servers on fresh roots, A in slot 0 and B in slot 1, peered with each
/// other; client 2 is the client of the test
struct announce_pair {
	announce_pair() {
		std::filesystem::remove_all("test-announce-a");
		std::filesystem::remove_all("test-announce-b");
		tctx.add_client(3);
		tctx.share_client_keys();
		network::enable_pk_handshake(tctx.client_context(0));
		network::enable_pk_handshake(tctx.client_context(1));
		a = std::make_unique<all_in_one>(tctx.client_context(0), params("test-announce-a", 0, 1));
		b = std::make_unique<all_in_one>(tctx.client_context(1), params("test-announce-b", 1, 0));
	}

	/// the parameters of the server in the slot, peered with the other one
	test::all_in_one_params params(std::string root, int slot, int peer) {
		return {.root = std::move(root), .slot = announce_slot(slot), .peers = {test::peer_of(announce_slot(peer), tctx.key_id(peer))}};
	}

	crypto::public_key_id key_a() { return tctx.key_id(0); }
	crypto::public_key_id key_b() { return tctx.key_id(1); }

	/// a data of the client, uploaded to A
	data_descriptor upload_to_a(protocol::storage_id const& sid, record_data_store& store, std::size_t size) {
		return upload_to(*a, tctx.client_context(2), tctx.key_id(2), sid, store, size);
	}

public:
	test::test_context tctx;
	std::unique_ptr<all_in_one> a;
	std::unique_ptr<all_in_one> b;
};

/// RD12's other shape: a record server without a data role (slot 2) and a data server
/// without a chain, dialing the record server's s2s listener; clients 2 and 3 transfer
struct separate_servers {
	separate_servers() {
		std::filesystem::remove_all("test-separate-records");
		std::filesystem::remove_all("test-separate-data");
		tctx.add_client(4);
		tctx.share_client_keys();
		network::enable_pk_handshake(record_context());
		network::enable_pk_handshake(data_context());
		// the data server does not know the record server's key before the link told it
		data_context().public_keys().remove(record_key());
		REQUIRE(!data_context().public_keys().find(record_key()));
		data = std::make_unique<data_server>(data_context(), data_params());
		records = std::make_unique<storage_server>(record_context(), record_params());
	}

	network::context& record_context() { return tctx.client_context(0); }
	network::context& data_context() { return tctx.client_context(1); }
	crypto::public_key_id record_key() { return tctx.key_id(0); }
	crypto::public_key_id data_key() { return tctx.key_id(1); }

	/// the data server as the record server tells the clients of it
	data_endpoint endpoint() {
		return data_endpoint{"127.0.0.1", ports.data, data_key(), {}, {}};
	}

	data_server_params data_params() {
		data_server_params p;
		p.enabled = true;
		p.storage_root = "test-separate-data";
		p.data_endpoint = test::loopback(ports.data);
		p.record_servers = {test::peer_of(announce_slot(2), record_key())};
		return p;
	}

	storage_server_params record_params() {
		storage_server_params p;
		p.storage_root = "test-separate-records";
		p.storage_server_endpoint = test::loopback(ports.client);
		p.s2s_endpoint = test::loopback(ports.s2s);
		p.data_servers = {endpoint()};
		return p;
	}

	/// the data server first: its link finds nobody, and comes back
	void start() {
		data->start();
		records->start();
		REQUIRE(records->s2s_local_endpoint().has_value());
		WAIT_REQUIRE(data->connected_record_servers() == std::vector<crypto::public_key_id>{record_key()}, 15s);
	}

	/// the record server anew on the same root, after it was closed
	void records_anew() {
		records = std::make_unique<storage_server>(record_context(), record_params());
		records->start();
	}

	/// the record server's part of a client's transfer, as its connection handler does it
	ticket_source tickets(std::shared_ptr<storage> const& storage, std::size_t client) {
		return test::tickets_of(*records, storage, record_context(), {endpoint()}, tctx.key_id(client));
	}

public:
	test::test_context tctx;
	test::test_ports ports{test::server_ports(announce_slot(2))};
	std::unique_ptr<data_server> data;
	std::unique_ptr<storage_server> records;
};

/// a storage of the record server with a committed data change naming the data, as a
/// client's commit leaves it
std::shared_ptr<storage> storage_naming(storage_server& records, protocol::storage_id const& sid, data_descriptor const& d) {
	auto storage = records.open_storage(sid, storage_modes{sync_mode::allow_all, auth_mode::only_tag});
	test::test_block_creator creator;
	REQUIRE(storage->commit_block(creator.test_user_change()).block);
	REQUIRE(storage->commit_block(creator.test_data_change_with_data(d)).block);
	return storage;
}

/// (RDS 9) the record naming the data is rolled back: the record server forgets the
/// holder, refuses tickets, and tells the data server over its link to drop the chunks
void rolled_back(separate_servers& servers, protocol::storage_id const& sid, data_id const& id) {
	auto reopened = servers.records->open_storage(sid);
	REQUIRE(reopened);
	REQUIRE(reopened->committed_data(id));
	CHECK(servers.data->find(sid, id));
	CHECK(reopened->truncate_from(sequence_number{2}).size() == 1);
	CHECK(!reopened->committed_data(id));
	CHECK(servers.records->availability().holdings(sid, id).empty());
	WAIT_CHECK(!servers.data->find(sid, id), 10s);
	CHECK(!std::filesystem::exists(std::filesystem::path{"test-separate-data"} / to_hex(sid) / "data" / to_hex(id)));
	CHECK(servers.data->stored_bytes() == 0);
}

}

// RD13: what a data role completes reaches the availability table of its own record role
// at once, the peers through the s2s announcement - and a link that comes up later gets
// the whole view, so a client on B is told that A has the data
TEST_CASE("data availability is announced to the peers", "[unit]") {
	announce_pair pair;
	auto const key_a = pair.key_a();
	record_data_store store{test::fresh_database("test-announce-client.db", "test-announce-client"), "test-announce-client"};
	auto const sid = securepath::test::random_octet_vector(16);

	// a data completed on A before B is there
	pair.a->start();
	auto const early = pair.upload_to_a(sid, store, 30000);
	auto const own = pair.a->records.availability().holdings(sid, early.manifest_digest);
	REQUIRE(own.size() == 1);
	CHECK(own[0] == data_holding{key_a, early.chunk_count(), early.chunk_count(), true});
	CHECK(pair.a->records.availability().load(key_a).stored_bytes == early.enc_size);

	// the link comes up: B learns what A holds
	pair.b->start();
	WAIT_CHECK(pair.b->records.availability().holdings(sid, early.manifest_digest).size() == 1, 10s);
	CHECK(pair.b->records.availability().holdings(sid, early.manifest_digest)[0].holder == key_a);

	// a data completed while the link is up is pushed
	auto const late = pair.upload_to_a(sid, store, 50000);
	WAIT_CHECK(pair.b->records.availability().holdings(sid, late.manifest_digest).size() == 1, 10s);
	auto const seen = pair.b->records.availability().holdings(sid, late.manifest_digest);
	REQUIRE(seen.size() == 1);
	CHECK(seen[0] == data_holding{key_a, late.chunk_count(), late.chunk_count(), true});
	WAIT_CHECK(pair.b->records.availability().load(key_a).stored_bytes == early.enc_size + late.enc_size, 5s);
	// A holds nothing of B's
	CHECK(pair.a->records.availability().load(pair.key_b()) == holder_load{});

	// the table is transient: a restarted A reads what its data role holds again
	pair.b->close();
	pair.b.reset();
	pair.a->close();
	all_in_one restarted{pair.tctx.client_context(0), {.root = "test-announce-a", .slot = announce_slot(0)}};
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
	separate_servers servers;
	servers.start();
	CHECK(servers.data_context().public_keys().find(servers.record_key()));
	// no replication peer: the record server talks records to nobody
	CHECK(servers.records->connected_peers().size() <= 1);

	// a storage with a committed data change, as a client's commit leaves it
	auto const sid = securepath::test::random_octet_vector(16);
	record_data_store store{test::fresh_database("test-announce-client.db", "test-announce-client"), "test-announce-client"};
	auto const key = test::test_group_key(1);
	auto const stored = test::store_data(store, 700000, chunk_size_range.lowest, key);
	auto const& made = stored.result;
	auto const& id = made.descriptor.manifest_digest;
	auto storage = storage_naming(*servers.records, sid, made.descriptor);

	// client 2 uploads with a ticket of the record server, to the data server
	REQUIRE(!test::upload(store, servers.tctx.client_context(2), servers.tickets(storage, 2), id));

	// the data server told the record server
	WAIT_CHECK(servers.records->availability().holdings(sid, id).size() == 1, 10s);
	auto const holdings = servers.records->availability().holdings(sid, id);
	REQUIRE(holdings.size() == 1);
	CHECK(holdings[0] == data_holding{servers.data_key(), made.descriptor.chunk_count(), made.descriptor.chunk_count(), true});
	CHECK(servers.records->availability().load(servers.data_key()).stored_bytes == made.descriptor.enc_size);

	// client 3 downloads
	record_data_store reader{test::fresh_database("test-separate-reader.db", "test-separate-reader"), "test-separate-reader"};
	auto handle = reader.open({key}, made.descriptor, made.header);
	REQUIRE(handle);
	CHECK(!test::download(reader, servers.tctx.client_context(3), servers.tickets(storage, 3), id));
	CHECK(test::read_all(*handle) == stored.plain);

	// a restarted record server gets the whole view again when the link comes back
	servers.records->close();
	storage.reset();
	servers.records_anew();
	WAIT_CHECK(servers.records->availability().holdings(sid, id).size() == 1, 30s);

	rolled_back(servers, sid, id);
	servers.records->close();
	servers.data->close();
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
	all_in_one server{tctx.client_context(0), {.root = "test-release-a", .slot = announce_slot(3)}};
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
