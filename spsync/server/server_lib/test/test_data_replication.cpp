#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/server/server_lib/data_server.hpp>
#include <spsync/server/server_lib/storage_server.hpp>
#include <spsync/server/server_lib/storage.hpp>
#include <spsync/server/server_lib/ticket_issuer.hpp>
#include <spsync/comm/data_downloader.hpp>
#include <spsync/comm/data_uploader.hpp>
#include <spsync/comm/net_data_channel.hpp>
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
	encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
	auto writer = store.create(key, chunk_size_range.lowest);
	writer.write(securepath::test::random_octet_vector(700000));
	return writer.finish();
}

/// the record server's part of a client's transfer, as its connection handler does it
ticket_source tickets_of(storage_server& records, std::shared_ptr<storage> const& storage, network::context& record_context
	, std::vector<data_endpoint> const& servers, crypto::public_key_id const& member) {
	return [&records, storage, &record_context, servers, member](data_descriptor const& d, data_right right
		, std::move_only_function<void(util::result<data_grant>)> cb) {
		ticket_issuer issuer{servers, records.availability(), 600s};
		auto issued = issuer.issue(storage->id(), storage->committed_data(d.manifest_digest), member
			, static_cast<std::uint32_t>(right), record_context.private_data().my_private_key(), clock_type::now());
		if(issued) {
			cb(util::result<data_grant>{data_grant{std::move(issued->ticket), std::move(issued->holders)}});
		} else {
			cb(util::result<data_grant>{issued.get_error()});
		}
	};
}

std::optional<error> upload(record_data_store& store, network::context& client_context, ticket_source source, data_id const& id) {
	net_data_channel channel{client_context, std::move(source)};
	std::atomic<int> done{0};
	std::mutex mutex;
	std::optional<error> result;
	data_uploader uploader{store, channel, data_upload_config{}, [&](data_id const&, std::optional<error> err) {
		std::unique_lock lock{mutex};
		result = std::move(err);
		++done;
	}};
	REQUIRE(uploader.enqueue(id));
	WAIT_REQUIRE(done == 1, 30s);
	std::unique_lock lock{mutex};
	return result;
}

bool holds(data_server& server, protocol::storage_id const& sid, data_id const& id) {
	auto const row = server.find(sid, id);
	return row && row->state == record_data_state::in_sync;
}

std::size_t complete_holders(storage_server const& records, protocol::storage_id const& sid, data_id const& id) {
	auto const holdings = records.availability().holdings(sid, id);
	return static_cast<std::size_t>(std::ranges::count_if(holdings, &data_holding::complete));
}

/// a record server and two data servers of their own (RD12), copy count 2
struct separate_cluster {
	separate_cluster()
	: record_context(tctx_init().client_context(0))
	{
		for(std::size_t i = 0; i != 3; ++i) {
			network::enable_pk_handshake(tctx.client_context(i));
		}
		for(std::size_t i = 0; i != 2; ++i) {
			endpoints.push_back(data_endpoint{"127.0.0.1", static_cast<std::uint16_t>(42802 + i), tctx.key_id(1 + i), {}, {}});
		}
		storage_server_params rparams;
		rparams.storage_root = "test-replication-records";
		rparams.storage_server_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 42800);
		rparams.s2s_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 42801);
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
		p.data_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), endpoints[i].port);
		p.record_servers = {peer_config{"127.0.0.1", 42801, tctx.key_id(0)}};
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
			CHECK(copy->read_chunk(id, chunk) == store.read_chunk(id, chunk));
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

/// an all-in-one replica (RD12): record role and data role over one context and root
struct replica {
	replica(test::test_context& tctx, std::size_t index, std::vector<data_endpoint> const& data_servers)
	: root("test-replication-replica-" + std::to_string(index))
	, records(tctx.client_context(index), record_params(tctx, index, data_servers))
	, data(tctx.client_context(index), data_params(tctx, index, data_servers))
	{
		records.attach_data_role(data);
	}

	static std::uint16_t port(std::size_t index, std::uint16_t what) {
		return static_cast<std::uint16_t>(42810 + 5 * index + what);
	}

	storage_server_params record_params(test::test_context& tctx, std::size_t index, std::vector<data_endpoint> const& data_servers) const {
		storage_server_params p;
		p.storage_root = root;
		p.storage_server_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), port(index, 0));
		p.s2s_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), port(index, 1));
		p.peers = {peer_config{"127.0.0.1", port(1 - index, 1), tctx.key_id(1 - index)}};
		p.data_servers = data_servers;
		p.data_copies = 2;
		return p;
	}

	data_server_params data_params(test::test_context& tctx, std::size_t index, std::vector<data_endpoint> const& data_servers) const {
		data_server_params p;
		p.enabled = true;
		p.storage_root = root;
		p.data_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), data_servers[index].port);
		// the other replica's tickets are good here: it hears of what is held through the
		// record roles' link, so no link of the data role's own
		p.record_servers = {peer_config{"", 0, tctx.key_id(1 - index)}};
		return p;
	}

	void start() {
		data.start();
		records.start();
	}

	void close() {
		records.close();
		data.close();
	}

	std::string root;
	storage_server records;
	data_server data;
};

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
		data_endpoint{"127.0.0.1", replica::port(0, 2), tctx.key_id(0), {}, {}},
		data_endpoint{"127.0.0.1", replica::port(1, 2), tctx.key_id(1), {}, {}}};

	replica a{tctx, 0, endpoints};
	replica b{tctx, 1, endpoints};
	a.start();
	b.start();
	WAIT_REQUIRE(!a.records.connected_peers().empty(), 15s);
	WAIT_REQUIRE(!b.records.connected_peers().empty(), 15s);

	// the same committed chain on both, as record replication leaves it
	auto const sid = securepath::test::random_octet_vector(16);
	record_data_store store{database::sqlite::create_sqlite_connection(client_db), client_root};
	auto const made = make_data(store);
	auto const& id = made.descriptor.manifest_digest;
	test::test_block_creator creator;
	auto const root_block = creator.test_user_change();
	auto const data_block = creator.test_data_change_with_data(made.descriptor);
	auto storage_a = a.records.open_storage(sid, storage_modes{sync_mode::allow_all, auth_mode::only_tag});
	auto storage_b = b.records.open_storage(sid, storage_modes{sync_mode::allow_all, auth_mode::only_tag});
	for(auto const& storage : {storage_a, storage_b}) {
		REQUIRE(storage->commit_block(root_block).block);
		REQUIRE(storage->commit_block(data_block).block);
	}

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
		CHECK(copy->read_chunk(id, chunk) == store.read_chunk(id, chunk));
	}

	storage_a.reset();
	storage_b.reset();
	b.close();
	a.close();
}

}
