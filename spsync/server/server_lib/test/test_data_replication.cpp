// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include "data_server_fixtures.hpp"
#include <spsync/server/server_lib/data_server.hpp>
#include <spsync/server/server_lib/storage_server.hpp>
#include <spsync/server/server_lib/storage.hpp>
#include <spsync/server/server_lib/ticket_issuer.hpp>
#include <spsync/transfer/data_downloader.hpp>
#include <spsync/transfer/data_uploader.hpp>
#include <spsync/transfer/net_data_channel.hpp>
#include <spsync/protocol/error.hpp>
#include <spsync/test/test_block_creator.hpp>
#include <spsync/test/test_context.hpp>
#include <spsync/util/result.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>
#include <securepath/util/conversions.hpp>

#include <atomic>
#include <filesystem>

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

std::string const client_root = "test-replication-client";
std::string const client_db = "test-replication-client.db";

void clean(std::vector<std::string> const& roots) {
	for(auto const& root : roots) {
		std::filesystem::remove_all(root);
	}
	std::filesystem::remove_all(client_root);
	std::remove(client_db.c_str());
}

/// a data as a client makes it, three chunks of the smallest size a chain takes
encrypted_data_result make_data(record_data_store& store) {
	return test::store_data(store, 700000, chunk_size_range.lowest).result;
}

/// the slots of this file's servers (test_ports.hpp): the separate cluster's record server
/// and its two data servers, then the two all-in-one replicas
int constexpr records_slot = test::replication_test_slots;
int data_slot(std::size_t i) {
	return test::replication_test_slots + 1 + static_cast<int>(i);
}
int replica_slot(std::size_t index) {
	return test::replication_test_slots + 3 + static_cast<int>(index);
}

using test::tickets_of;
using test::upload;
using test::holds;
using test::complete_holders;

/// a record server and two data servers of their own (RD12), copy count 2
struct separate_cluster {
	separate_cluster()
	: record_context(tctx_init().client_context(0))
	{
		for(std::size_t i = 0; i != 3; ++i) {
			network::enable_pk_handshake(tctx.client_context(i));
		}
		for(std::size_t i = 0; i != 2; ++i) {
			endpoints.push_back(data_endpoint{"127.0.0.1", test::server_ports(data_slot(i)).data, tctx.key_id(1 + i), {}, {}});
		}
		storage_server_params rparams;
		rparams.storage_root = "test-replication-records";
		rparams.storage_server_endpoint = test::loopback(test::server_ports(records_slot).client);
		rparams.s2s_endpoint = test::loopback(test::server_ports(records_slot).s2s);
		rparams.data_servers = endpoints;
		rparams.data_copies = 2;
		rparams.replication_interval = 2s;
		records = std::make_unique<storage_server>(record_context, rparams);
	}

	test::test_context& tctx_init() {
		clean({"test-replication-records", "test-replication-data-0", "test-replication-data-1"});
		tctx.add_client(4);
		tctx.share_client_keys();
		return tctx;
	}

	std::unique_ptr<data_server> make_data_server(std::size_t i) {
		data_server_params p;
		p.enabled = true;
		p.storage_root = "test-replication-data-" + std::to_string(i);
		p.data_endpoint = test::loopback(endpoints[i].port);
		p.record_servers = {test::peer_of(records_slot, tctx.key_id(0))};
		// what members may move in an hour is next to nothing: copies do not count
		p.transfer = transfer_quota{1000, 3600s};
		return std::make_unique<data_server>(tctx.client_context(1 + i), p);
	}

	void start_data_server(std::size_t i) {
		data[i] = make_data_server(i);
		data[i]->start();
		WAIT_REQUIRE(data[i]->connected_record_servers().size() == 1, 15s);
	}

	/// the index of the data server a client's upload of the data goes to
	std::size_t first_holder(data_id const& id) const {
		return upload_order(endpoints, id).front().key == endpoints[0].key ? 0 : 1;
	}

	~separate_cluster() {
		for(auto& server : data) {
			if(server) {
				server->close();
			}
		}
		records->close();
	}

	test::test_context tctx;
	network::context& record_context;
	std::vector<data_endpoint> endpoints;
	std::unique_ptr<storage_server> records;
	std::array<std::unique_ptr<data_server>, 2> data;
};

}

// RD13 copy count, RDS 10: the record server looks after the copies - it knows what is
// committed, who holds what and signs the tickets - and a data server pulls from another
// one the way a member does
TEST_CASE("data copies among separate data servers", "[unit]") {
	separate_cluster cluster;
	auto& records = *cluster.records;
	records.start();

	auto const sid = securepath::test::random_octet_vector(16);
	auto storage = records.open_storage(sid, storage_modes{sync_mode::allow_all, auth_mode::only_tag});
	record_data_store store{database::sqlite::create_sqlite_connection(client_db), client_root};
	auto const made = make_data(store);
	auto const& id = made.descriptor.manifest_digest;
	test::test_block_creator creator;
	REQUIRE(storage->commit_block(creator.test_user_change()).block);
	REQUIRE(storage->commit_block(creator.test_data_change_with_data(made.descriptor)).block);
	auto const first = cluster.first_holder(id);
	auto const second = 1 - first;
	auto const client_tickets = tickets_of(records, storage, cluster.record_context, cluster.endpoints, cluster.tctx.key_id(3));

	SECTION("a completed upload is copied to the other primary holder") {
		cluster.start_data_server(0);
		cluster.start_data_server(1);
		REQUIRE(!upload(store, cluster.tctx.client_context(3), client_tickets, id));
		CHECK(holds(*cluster.data[first], sid, id));

		WAIT_REQUIRE(holds(*cluster.data[second], sid, id), 30s);
		WAIT_CHECK(complete_holders(records, sid, id) == 2, 10s);
		CHECK(cluster.data[second]->pending_replications() == 0);
		// the same bytes, verified chunk by chunk against the manifest on the way
		auto const copy = cluster.data[second]->open_store(sid);
		for(std::uint64_t chunk = 0; chunk != made.descriptor.chunk_count(); ++chunk) {
			CHECK(copy->chunks().read_chunk(id, chunk) == store.read_chunk(id, chunk));
		}
		// it reserved its size like an upload
		CHECK(cluster.data[second]->stored_bytes() == made.descriptor.enc_size);
	}

	SECTION("a data server that was away gets its copies when its link comes up") {
		cluster.start_data_server(first);
		REQUIRE(!upload(store, cluster.tctx.client_context(3), client_tickets, id));
		WAIT_REQUIRE(complete_holders(records, sid, id) == 1, 10s);

		cluster.start_data_server(second);
		WAIT_REQUIRE(holds(*cluster.data[second], sid, id), 30s);
		WAIT_CHECK(complete_holders(records, sid, id) == 2, 10s);
	}

	SECTION("a data server that lost its disk gets its copies again") {
		cluster.start_data_server(0);
		cluster.start_data_server(1);
		REQUIRE(!upload(store, cluster.tctx.client_context(3), client_tickets, id));
		WAIT_REQUIRE(holds(*cluster.data[second], sid, id), 30s);
		WAIT_REQUIRE(complete_holders(records, sid, id) == 2, 10s);

		cluster.data[second]->close();
		cluster.data[second].reset();
		std::filesystem::remove_all("test-replication-data-" + std::to_string(second));
		// what it said before is void when it tells everything anew - nothing, now
		cluster.start_data_server(second);
		WAIT_REQUIRE(holds(*cluster.data[second], sid, id), 30s);
		WAIT_CHECK(complete_holders(records, sid, id) == 2, 10s);
	}

	SECTION("a release that was missed is made up for") {
		cluster.start_data_server(0);
		cluster.start_data_server(1);
		REQUIRE(!upload(store, cluster.tctx.client_context(3), client_tickets, id));
		WAIT_REQUIRE(holds(*cluster.data[second], sid, id), 30s);
		WAIT_REQUIRE(complete_holders(records, sid, id) == 2, 10s);

		// one data server is away when the record goes
		cluster.data[second]->close();
		cluster.data[second].reset();
		CHECK(storage->truncate_from(sequence_number{2}).size() == 1);
		WAIT_CHECK(!cluster.data[first]->find(sid, id), 10s);

		// it still holds the data and says so when it is back: the storage replicates to
		// nobody, so what it does not know is dead
		cluster.start_data_server(second);
		WAIT_CHECK(!cluster.data[second]->find(sid, id), 30s);
		CHECK(complete_holders(records, sid, id) == 0);
	}

	storage.reset();
}

namespace {

/// an all-in-one replica (RD12): both roles over one context and root, peered with the
/// other one. The other replica's tickets are good at the data role: it hears of what is
/// held through the record roles' link, so no link of the data role's own
test::all_in_one_params replica_params(test::test_context& tctx, std::size_t index, std::vector<data_endpoint> const& data_servers) {
	test::all_in_one_params p;
	p.root = "test-replication-replica-" + std::to_string(index);
	p.slot = replica_slot(index);
	p.peers = {test::peer_of(replica_slot(1 - index), tctx.key_id(1 - index))};
	p.data_servers = data_servers;
	p.trusted_record_servers = {peer_config{"", 0, tctx.key_id(1 - index)}};
	return p;
}

/// the same committed chain naming the data on both replicas, as record replication
/// leaves it: the storage of each
std::vector<std::shared_ptr<storage>> same_chain_on(std::vector<test::all_in_one*> const& replicas, protocol::storage_id const& sid
	, data_descriptor const& d) {
	test::test_block_creator creator;
	auto const root_block = creator.test_user_change();
	auto const data_block = creator.test_data_change_with_data(d);
	std::vector<std::shared_ptr<storage>> ret;
	for(auto* replica : replicas) {
		ret.push_back(replica->records.open_storage(sid, storage_modes{sync_mode::allow_all, auth_mode::only_tag}));
		REQUIRE(ret.back()->commit_block(root_block).block);
		REQUIRE(ret.back()->commit_block(data_block).block);
	}
	return ret;
}

}

// the other shape: every replica has both roles. A record role looks after its own data
// role only - the peer's record role hears of the same copies and does the same
TEST_CASE("data copies among all in one replicas", "[unit]") {
	clean({"test-replication-replica-0", "test-replication-replica-1"});
	test::test_context tctx;
	tctx.add_client(3);
	tctx.share_client_keys();
	network::enable_pk_handshake(tctx.client_context(0));
	network::enable_pk_handshake(tctx.client_context(1));
	std::vector<data_endpoint> const endpoints{
		data_endpoint{"127.0.0.1", test::server_ports(replica_slot(0)).data, tctx.key_id(0), {}, {}},
		data_endpoint{"127.0.0.1", test::server_ports(replica_slot(1)).data, tctx.key_id(1), {}, {}}};

	test::all_in_one a{tctx.client_context(0), replica_params(tctx, 0, endpoints)};
	test::all_in_one b{tctx.client_context(1), replica_params(tctx, 1, endpoints)};
	a.start();
	b.start();
	WAIT_REQUIRE(!a.records.connected_peers().empty(), 15s);
	WAIT_REQUIRE(!b.records.connected_peers().empty(), 15s);

	// the same committed chain on both, as record replication leaves it
	auto const sid = securepath::test::random_octet_vector(16);
	record_data_store store{database::sqlite::create_sqlite_connection(client_db), client_root};
	auto const made = make_data(store);
	auto const& id = made.descriptor.manifest_digest;
	auto storages = same_chain_on({&a, &b}, sid, made.descriptor);
	auto& storage_a = storages[0];

	// a client of A uploads: to whichever data role the placement says
	auto const first_is_a = upload_order(endpoints, id).front().key == tctx.key_id(0);
	REQUIRE(!upload(store, tctx.client_context(2), tickets_of(a.records, storage_a, tctx.client_context(0), endpoints, tctx.key_id(2)), id));
	auto& first = first_is_a ? a : b;
	auto& second = first_is_a ? b : a;
	CHECK(holds(first.data, sid, id));

	// the other replica's record role hears of it and has its own data role pull a copy,
	// with a ticket it signs itself
	WAIT_REQUIRE(holds(second.data, sid, id), 30s);
	WAIT_CHECK(complete_holders(a.records, sid, id) == 2, 10s);
	WAIT_CHECK(complete_holders(b.records, sid, id) == 2, 10s);
	auto const copy = second.data.open_store(sid);
	for(std::uint64_t chunk = 0; chunk != made.descriptor.chunk_count(); ++chunk) {
		CHECK(copy->chunks().read_chunk(id, chunk) == store.read_chunk(id, chunk));
	}

	storages.clear();
	b.close();
	a.close();
}

}
