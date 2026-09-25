// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/client_sync.hpp>
#include <spsync/core/data/source_record_data.hpp>
#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>
#include <spsync/core/records/user_change_record.hpp>

#include <spsync/test/test_context.hpp>
#include <spsync/test/test_server_runner.hpp>
#include <spsync/test/util.hpp>

#include <securepath/crypto/hash.hpp>
#include <securepath/crypto/private_data_access.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <future>
#include <mutex>
#include <thread>

// record_data.txt RDS 7: record data end to end, as an application sees it - real clients,
// a real all-in-one server, files as sources, connections that go away in the middle

namespace securepath::sync::client::test {
namespace {

using namespace std::chrono_literals;

std::string const server_root = "record_data_system_root";

struct system_net {
	system_net(network::context& context, event_system::event_handler& handler)
	: net(context, handler)
	{}
	network_connection net;
};

/// a member that can lose its connection and come back
class system_client : public event_system::event_handler, public system_net, public client_sync {
public:
	system_client(event_system::event_loop& loop, network::context& context, std::string const& name)
	: event_handler(loop)
	, system_net(context, *this)
	, client_sync(context, loop, sync::test::create_test_database(name + ".db"), make_config(name))
	{}

	~system_client() {
		client_sync::stop_handler();
		event_handler::stop_handler();
	}

	static sync_engine_config make_config(std::string const& name) {
		std::filesystem::remove_all(name);
		sync_engine_config config;
		config.data_root = name;
		return config;
	}

	void connect() {
		net.connect("127.0.0.1", default_storage_server_port);
	}

	/// as if the client was killed: the record connection and with it the data connections
	void disconnect() {
		net.close();
	}

	void handle_event(std::unique_ptr<event_base> ev) override {
		dispatch(*ev
				, event_dest<events::on_connect>(&system_client::on_connect)
				, event_dest<events::on_disconnect>(&system_client::on_disconnect)
				, event_dest<events::on_create_storage>(&system_client::on_create_storage));
	}

	void on_connect() { connected = true; }
	void on_disconnect(error const&) { connected = false; }

	void on_create_storage(storage_id const& sid, error const& err) {
		if(!err) {
			init(sid, net);
		}
		created = !err;
	}

	void on_data_change(record_handle rec, std::deque<single_data_change>) override {
		std::unique_lock l{mutex};
		records.push_back(std::move(rec));
	}

	void on_user_change(record_handle, user_change) override {
		++user_changes;
	}

	void on_data_state_changed(data_id id, record_data_state state) override {
		std::unique_lock l{mutex};
		states.emplace_back(std::move(id), state);
	}

	std::size_t record_count() const {
		std::unique_lock l{mutex};
		return records.size();
	}

	record_handle record(std::size_t n) const {
		std::unique_lock l{mutex};
		return records.at(n);
	}

	std::size_t in_sync_count() const {
		std::unique_lock l{mutex};
		return static_cast<std::size_t>(std::ranges::count_if(states, [](auto const& s) { return s.second == record_data_state::in_sync; }));
	}

public:
	std::atomic<bool> connected{false};
	std::atomic<bool> created{false};
	std::atomic<int> user_changes{0};
	mutable std::mutex mutex;
	std::deque<record_handle> records;
	std::deque<std::pair<data_id, record_data_state>> states;
};

/// a file of the given size with content nobody has to keep in memory; returns its sha3
octet_vector write_source_file(std::filesystem::path const& path, std::uint64_t size) {
	crypto::hash_stream hash;
	std::ofstream out(path, std::ios::binary | std::ios::trunc);
	std::uint64_t pos = 0;
	while(pos < size) {
		auto const piece = securepath::test::random_octet_vector(static_cast<std::size_t>(std::min<std::uint64_t>(1024 * 1024, size - pos)));
		out.write(reinterpret_cast<char const*>(piece.data()), static_cast<std::streamsize>(piece.size()));
		hash.update(piece);
		pos += piece.size();
	}
	return hash.final();
}

/// sha3 of what a data reads as, in pieces
octet_vector content_hash(record_data& data) {
	crypto::hash_stream hash;
	octet_vector piece(1024 * 1024);
	std::uint64_t pos = 0;
	std::uint64_t n = data.read(pos, piece.data(), piece.size());
	while(n != 0) {
		hash.update(octet_span{piece}.first(static_cast<std::size_t>(n)));
		pos += n;
		n = data.read(pos, piece.data(), piece.size());
	}
	return hash.final();
}

/// wait until the value is strictly between the bounds, or past the upper one; the value seen
template<typename F>
std::uint64_t wait_for_progress(F value, std::uint64_t at_least, std::uint64_t total, std::chrono::seconds limit) {
	auto const deadline = std::chrono::steady_clock::now() + limit;
	std::uint64_t v = value();
	while(v < at_least && v < total && std::chrono::steady_clock::now() < deadline) {
		std::this_thread::sleep_for(1ms);
		v = value();
	}
	return v;
}

/**
 * A big object from one member to another over the server, both directions interrupted:
 * the author loses its connection in the middle of the upload, the reader in the middle
 * of the download; each comes back and the transfer goes on from what had arrived. Then
 * the mobile case: many objects, one of them asked for.
 */
void transfer_with_interruptions(std::uint64_t size) {
	event_system::single_thread_event_loop loop;
	sync::test::test_context net_context;
	net_context.add_client(2);
	net_context.add_client_keys_for_server();
	net_context.share_client_keys();

	std::filesystem::remove_all(server_root);
	auto const server_key = crypto::my_private_key(net_context.server_context().private_data());
	spsync_server_params params;
	params.storage_params.storage_root = server_root;
	params.storage_params.data_servers = {data_endpoint{"127.0.0.1", default_data_server_port, server_key.id(), {}, {}}};
	params.data_params.enabled = true;
	params.data_params.storage_root = server_root;
	sync::test::test_server server(net_context.server_context(), params);
	server.run();
	REQUIRE(server.data().local_endpoint().has_value());

	system_client author(loop, net_context.client_context(0), "record_data_system_author");
	system_client reader(loop, net_context.client_context(1), "record_data_system_reader");
	author.connect();
	reader.connect();
	WAIT_REQUIRE(author.connected.load(), 10s);
	WAIT_REQUIRE(reader.connected.load(), 10s);
	auto const sid = author.net.create_storage();
	WAIT_REQUIRE(author.created.load(), 10s);
	reader.init(sid, reader.net);

	users us(users_change_mode::full);
	us.add(util::user_access{net_context.key_id(0), util::access_type::user_management_access});
	us.add(util::user_access{net_context.key_id(1), util::access_type::user_management_access});
	author.send_user_change(us);
	WAIT_REQUIRE(author.user_changes == 1, 5s);
	WAIT_REQUIRE(reader.user_changes == 1, 5s);

	// -- the upload, interrupted --
	std::filesystem::path const source = "record_data_system_source.bin";
	auto const expected = write_source_file(source, size);
	auto sent = author.send_data_change(util::create_object_id(), util::metadata{}, std::make_shared<file_record_data>(source));
	REQUIRE(sent);
	auto own = author.object_data(sent);
	REQUIRE(own);
	CHECK(own->size() == size);
	WAIT_REQUIRE(reader.record_count() == 1, 10s);
	auto remote = reader.object_data(reader.record(0));
	REQUIRE(remote);
	auto const id = sent->record().deserialise_to<data_change_record>().begin()->data.data.value().manifest_digest;
	auto const chunks = sent->record().deserialise_to<data_change_record>().begin()->data.data.value().chunk_count();

	auto const held_at_server = [&]() -> std::uint64_t {
		auto const row = server.data().find(sid, id);
		return row ? row->have.count() : 0;
	};
	auto const at_kill = wait_for_progress(held_at_server, 2, chunks, 60s);
	author.disconnect();
	WAIT_REQUIRE(!author.connected.load(), 10s);
	// the connection went in the middle of it
	CHECK(at_kill >= 2);
	CHECK(at_kill < chunks);
	CHECK(own->state() == record_data_state::upload_pending);
	std::this_thread::sleep_for(500ms);
	auto const held_while_away = held_at_server();
	CHECK(held_while_away < chunks);

	author.connect();
	WAIT_REQUIRE(author.connected.load(), 10s);
	WAIT_REQUIRE(own->state() == record_data_state::in_sync, 120s);
	CHECK(held_at_server() == chunks);
	// what had arrived before stayed: the server never started over
	CHECK(held_while_away >= at_kill);

	// -- the download, interrupted --
	CHECK(remote->state() == record_data_state::deferred);
	auto fetched = reader.fetch_object_data(reader.record(0));
	REQUIRE(fetched);
	auto const chunk_octets = size / chunks;
	auto const got_at_kill = wait_for_progress([&] { return fetched->available_size(); }, 2 * chunk_octets, size, 60s);
	reader.disconnect();
	WAIT_REQUIRE(!reader.connected.load(), 10s);
	CHECK(got_at_kill >= 2 * chunk_octets);
	CHECK(got_at_kill < size);
	WAIT_CHECK(fetched->state() == record_data_state::download_pending, 10s);
	auto const kept = fetched->available_size();
	CHECK(kept >= got_at_kill);
	CHECK(kept < size);

	reader.connect();
	WAIT_REQUIRE(reader.connected.load(), 10s);
	WAIT_REQUIRE(fetched->state() == record_data_state::in_sync, 120s);
	CHECK(fetched->available_size() == size);
	CHECK(content_hash(*fetched) == expected);
	std::filesystem::remove(source);

	// -- mobile: many objects, one of them wanted --
	std::size_t const many = 20;
	std::vector<octet_vector> contents;
	for(std::size_t i = 0; i != many; ++i) {
		contents.push_back(securepath::test::random_octet_vector(40000 + i));
		author.send_data_change(util::create_object_id(), util::metadata{}, std::make_shared<memory_record_data>(contents.back()));
	}
	WAIT_REQUIRE(reader.record_count() == 1 + many, 30s);
	WAIT_REQUIRE(author.in_sync_count() == 1 + many, 60s);

	std::size_t const wanted = 7;
	auto one = reader.fetch_object_data(reader.record(1 + wanted));
	REQUIRE(one);
	WAIT_REQUIRE(one->state() == record_data_state::in_sync, 30s);
	octet_vector read_back(contents[wanted].size());
	CHECK(one->read(0, read_back.data(), read_back.size()) == read_back.size());
	CHECK(read_back == contents[wanted]);
	std::this_thread::sleep_for(500ms);
	for(std::size_t i = 0; i != many; ++i) {
		if(i != wanted) {
			auto other = reader.object_data(reader.record(1 + i));
			REQUIRE(other);
			CHECK(other->state() == record_data_state::deferred);
			CHECK(other->available_size() == 0);
		}
	}
}

}

// the everyday size: runs with the rest
TEST_CASE("record data system transfer", "[system]") {
	transfer_with_interruptions(std::uint64_t{48} * 1024 * 1024 + 12345);
}

// RDS 7 asks for multi-hundred-MB: the same with 300 MiB, run explicitly with "[.system]"
TEST_CASE("record data system transfer of a big object", "[.system]") {
	transfer_with_interruptions(std::uint64_t{300} * 1024 * 1024 + 12345);
}

}
