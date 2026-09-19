#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/server/server_lib/data_server.hpp>
#include <spsync/server/server_lib/storage_server.hpp>
#include <spsync/comm/data_uploader.hpp>
#include <spsync/comm/net_data_channel.hpp>
#include <spsync/test/test_context.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>

#include <atomic>
#include <filesystem>

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

/// an all-in-one server (RD12): record role and data role over one context and root
struct all_in_one {
	all_in_one(network::context& context, std::string root, std::uint16_t port, std::uint16_t s2s_port, std::vector<peer_config> peers)
	: root(std::move(root))
	, records(context, record_params(this->root, port, s2s_port, std::move(peers)))
	, data(context, data_params(this->root))
	{
		records.attach_data_role(data);
	}

	static storage_server_params record_params(std::string const& root, std::uint16_t port, std::uint16_t s2s_port, std::vector<peer_config> peers) {
		storage_server_params p;
		p.storage_root = root;
		p.storage_server_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), port);
		p.s2s_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), s2s_port);
		p.peers = std::move(peers);
		return p;
	}

	static data_server_params data_params(std::string const& root) {
		data_server_params p;
		p.enabled = true;
		p.storage_root = root;
		p.data_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0);
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

/// upload one data to the server's data role with a ticket the server signs for itself
data_descriptor upload_to(all_in_one& server, network::context& server_context, network::context& client_context
	, crypto::public_key_id const& client, protocol::storage_id const& sid, record_data_store& store, std::size_t size) {
	encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
	auto writer = store.create(key, 4096);
	writer.write(securepath::test::random_octet_vector(size));
	auto const descriptor = writer.finish().descriptor;

	auto const server_key = crypto::my_private_key(server_context.private_data());
	data_endpoint const endpoint{"127.0.0.1", server.data.local_endpoint()->port(), server_key.id(), {}, {}};
	ticket_source source = [&, endpoint](data_descriptor const& d, data_right right, std::move_only_function<void(util::result<data_grant>)> cb) {
		data_ticket ticket{sid, d, client, right, clock_type::now() + 10min};
		ticket.sign(server_key);
		cb(util::result<data_grant>{data_grant{std::move(ticket), {endpoint}}});
	};

	net_data_channel channel{client_context, source};
	std::atomic<int> done{0};
	std::atomic<bool> failed{false};
	data_uploader uploader{store, channel, data_upload_config{}, [&](data_id const&, std::optional<error> err) {
		failed = err.has_value();
		++done;
	}};
	REQUIRE(uploader.enqueue(descriptor.manifest_digest));
	WAIT_REQUIRE(done == 1, 20s);
	REQUIRE(!failed);
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

	all_in_one a{tctx.client_context(0), "test-announce-a", 42770, 42780, {peer_config{"127.0.0.1", 42781, key_b}}};
	auto b = std::make_unique<all_in_one>(tctx.client_context(1), "test-announce-b", 42771, 42781
		, std::vector<peer_config>{peer_config{"127.0.0.1", 42780, key_a}});

	record_data_store store{database::sqlite::create_sqlite_connection("test-announce-client.db"), "test-announce-client"};
	auto const sid = securepath::test::random_octet_vector(16);

	// a data completed on A before B is there
	a.start();
	auto const early = upload_to(a, tctx.client_context(0), tctx.client_context(2), tctx.key_id(2), sid, store, 30000);
	auto const own = a.records.availability().holdings(sid, early.manifest_digest);
	REQUIRE(own.size() == 1);
	CHECK(own[0] == data_holding{key_a, early.chunk_count(), early.chunk_count(), true});
	CHECK(a.records.availability().load(key_a).stored_bytes == early.enc_size);

	// the link comes up: B learns what A holds
	b->start();
	WAIT_CHECK(b->records.availability().holdings(sid, early.manifest_digest).size() == 1, 10s);
	CHECK(b->records.availability().holdings(sid, early.manifest_digest)[0].holder == key_a);

	// a data completed while the link is up is pushed
	auto const late = upload_to(a, tctx.client_context(0), tctx.client_context(2), tctx.key_id(2), sid, store, 50000);
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
	all_in_one restarted{tctx.client_context(0), "test-announce-a", 42770, 42780, {}};
	restarted.start();
	CHECK(restarted.records.availability().holdings(sid, early.manifest_digest).size() == 1);
	CHECK(restarted.records.availability().holdings(sid, late.manifest_digest).size() == 1);
	restarted.close();
}

}
