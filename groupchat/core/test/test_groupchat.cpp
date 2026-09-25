#include <groupchat/core/groupchat.hpp>
#include <groupchat/core/events.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/events.hpp>
#include <spsync/test/test_server_runner.hpp>
#include <spsync/test/test_context.hpp>

#include <spsync/core/data/data_ticket.hpp>
#include <spsync/protocol/ports.hpp>

#include <securepath/crypto/hash.hpp>
#include <securepath/crypto/private_data_access.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <set>

namespace securepath::groupchat::test {

using namespace securepath::sync;

class test_groupchat : public event_system::event_handler, public groupchat {
public:
	test_groupchat(network::context& context, event_system::event_loop& loop, groupchat_config config = {})
	: event_handler(loop)
	, groupchat(*this, context, std::move(config))
	{}

	~test_groupchat() {
		stop_handler();
	}

	/// called when server connected
	void on_connect(server_id) {
		connected.set_value(error{});
	}
	/// called when server disconnected
	void on_disconnect(server_id, error err) {
		connected.set_value(err);
	}
	/// called when chat created or creating failed
	void on_create(server_chat_id id, sync::users change, error err) {
		if(err) {
			created.set_exception(std::make_exception_ptr(err));
		} else {
			created.set_value(id.cid);
		}

	}
	/// called when user changed or failed
	void on_change_user(server_chat_id id, sync::users change, error) {
	}

	/// called when chat joined or it failed
	void on_join(server_chat_id id, sync::users, error err) {
		if(err) {
			joined.set_exception(std::make_exception_ptr(err));
		} else {
			joined.set_value(id.cid);
		}

	}
	/// called when chat message received (own committed messages included)
	void on_message(server_chat_id id, msg_data md, msg_change change) {
		std::unique_lock l{mutex};
		received.insert(md.message);
	}

	/// called when the packet server connection is up
	void on_packet_connect() {
		try { packet_connected.set_value(); } catch(...) {}
	}

	void on_packet_disconnect(error) {
	}

	/// called when a chat invitation arrives (fires again after verification, hence the guard)
	void on_invitation(sync::client::request req, sync::client::storage_info, std::string, std::string) {
		try { invitation.set_value(req.id); } catch(...) {}
	}

	/// a file shared with a chat (own or another member's)
	void on_file(server_chat_id, file_entry, file_change) {
		++files;
	}

	/// the transfer state of a shared file changed
	void on_file_state(server_chat_id, file_id, file_state state, error err) {
		std::unique_lock l{mutex};
		file_states.push_back(state);
		file_errors += err ? 1 : 0;
	}

	bool saw_file_state(file_state wanted) {
		std::unique_lock l{mutex};
		return std::ranges::find(file_states, wanted) != file_states.end();
	}

	bool has_message(std::string const& m) {
		std::unique_lock l{mutex};
		return received.count(m) != 0;
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		namespace gc_ev = securepath::groupchat::events;
		dispatch( *ev
			, event_dest<gc_ev::on_connect>(&test_groupchat::on_connect)
			, event_dest<gc_ev::on_disconnect>(&test_groupchat::on_disconnect)
			, event_dest<gc_ev::on_create>(&test_groupchat::on_create)
			, event_dest<gc_ev::on_change_user>(&test_groupchat::on_change_user)
			, event_dest<gc_ev::on_join>(&test_groupchat::on_join)
			, event_dest<gc_ev::on_message>(&test_groupchat::on_message)
			, event_dest<sync::client::events::on_connect>(&test_groupchat::on_packet_connect)
			, event_dest<sync::client::events::on_disconnect>(&test_groupchat::on_packet_disconnect)
			, event_dest<sync::client::events::on_invitation>(&test_groupchat::on_invitation)
			, event_dest<gc_ev::on_file>(&test_groupchat::on_file)
			, event_dest<gc_ev::on_file_state>(&test_groupchat::on_file_state) );
	}


	std::promise<error> connected;
	std::promise<chat_id> created;
	std::promise<chat_id> joined;
	std::promise<void> packet_connected;
	std::promise<sync::client::request_id> invitation;
	std::mutex mutex;
	std::set<std::string> received;
	std::atomic<int> files{0};
	std::deque<file_state> file_states;
	int file_errors{};
};

namespace {

/// a server with the data role, the way a deployment enables it
spsync_server_params data_role_params(sync::test::test_context& net_context) {
	std::filesystem::remove_all("gc_test_server");
	auto const server_key = crypto::my_private_key(net_context.server_context().private_data());
	spsync_server_params params;
	params.storage_params.storage_root = "gc_test_server";
	params.storage_params.data_servers = {data_endpoint{"127.0.0.1", sync::default_data_server_port, server_key.id(), {}, {}}};
	params.data_params.enabled = true;
	params.data_params.storage_root = "gc_test_server";
	return params;
}

/// a file of random content; its sha3
octet_vector write_random_file(std::filesystem::path const& path, std::size_t size) {
	auto const content = securepath::test::random_octet_vector(size);
	std::ofstream out(path, std::ios::binary | std::ios::trunc);
	out.write(reinterpret_cast<char const*>(content.data()), static_cast<std::streamsize>(content.size()));
	crypto::hash_stream hash;
	hash.update(content);
	return hash.final();
}

/// the sha3 of a file
octet_vector file_digest(std::filesystem::path const& path) {
	std::ifstream in(path, std::ios::binary);
	octet_vector content{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
	crypto::hash_stream hash;
	hash.update(content);
	return hash.final();
}

/// alice and bob in the chat "room" over a server with the data role: the invite and join
/// dance of the invite test
struct chat_pair {
	chat_pair()
	: server(net_context.server_context(), data_role_params(net_context))
	{
		net_context.add_client(2);
		std::filesystem::remove_all("gc_test_c0");
		std::filesystem::remove_all("gc_test_c1");
		std::filesystem::create_directories("gc_test_c0");
		std::filesystem::create_directories("gc_test_c1");
		server.run();
		alice = std::make_unique<test_groupchat>(net_context.client_context(0), loop, groupchat_config{"gc_test_c0"});
		alice->create_account(hp, "alice");
		alice->connect();
		REQUIRE(alice->packet_connected.get_future().wait_for(5s) == std::future_status::ready);
		conn0 = alice->load(hp.sync_server());
		conn0->connect().get();
		cid = conn0->create_chat("room").id();
		REQUIRE(alice->created.get_future().wait_for(5s) == std::future_status::ready);

		bob = std::make_unique<test_groupchat>(net_context.client_context(1), loop, groupchat_config{"gc_test_c1"});
		bob->create_account(hp, "bob");
		bob->connect();
		REQUIRE(bob->packet_connected.get_future().wait_for(5s) == std::future_status::ready);
		alice->send_chat_invitation(user{user_id{net_context.key_id(1)}, hp.key_server()}, "join us", cid);
		auto inv = bob->invitation.get_future();
		REQUIRE(inv.wait_for(5s) == std::future_status::ready);
		conn1 = bob->load(hp.sync_server());
		conn1->connect().get();
		bob->join_chat(inv.get());
		REQUIRE(bob->joined.get_future().wait_for(5s) == std::future_status::ready);
	}

	sync::test::test_context net_context;
	sync::test::test_server server;
	gc_servers hp{"127.0.0.1", sync::default_key_server_port, sync::default_storage_server_port, packet_transport::default_packet_server_port};
	event_system::single_thread_event_loop loop;
	std::unique_ptr<test_groupchat> alice;
	std::unique_ptr<test_groupchat> bob;
	std::shared_ptr<chat_connection> conn0;
	std::shared_ptr<chat_connection> conn1;
	chat_id cid;
};

}

TEST_CASE("groupchat_test", "[system]") {
	std::remove(groupchat_config{}.db().c_str());

	sync::test::test_context net_context;
	net_context.add_client(3);

	sync::test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	chat_id cid;

	gc_servers hp{"127.0.0.1", sync::default_key_server_port, sync::default_storage_server_port, packet_transport::default_packet_server_port};
	event_system::single_thread_event_loop loop;
	{
		test_groupchat client(net_context.client_context(0), loop);

		CHECK(!client.account_info());

		client.create_account(hp, "test");

		auto info = client.account_info();
		REQUIRE(info);
		CHECK(info->server == hp.sync_server());
		CHECK(info->name == "test");
		CHECK(info->me.is_valid());

		auto conn = client.load(hp.sync_server());

		conn->connect();
		{
			auto f = client.connected.get_future();
			REQUIRE(f.wait_for(2s) == std::future_status::ready);
			REQUIRE(!f.get());
		}

		cid = conn->create_chat("test").id();
		{
			auto f = client.created.get_future();
			REQUIRE(f.wait_for(2s) == std::future_status::ready);
			REQUIRE(f.get() == cid);
			CHECK(client.channel_ids().find_server(cid));
		}
	}
	{
		test_groupchat client(net_context.client_context(0), loop);

		auto info = client.account_info();
		REQUIRE(info);
		CHECK(info->server == hp.sync_server());
		CHECK(info->name == "test");
		CHECK(info->me.is_valid());
		CHECK(client.channel_ids().find_server(cid));

		auto ids = client.load_channels();
		CHECK(ids.size() == 1);
		//t: implement rest
	}
}


// two accounts: create a chat, invite over the packet server, join from the invitation
// request, message both ways and reload the joiner from disk
TEST_CASE("groupchat invite join message test", "[system]") {
	std::filesystem::remove_all("gc_test_c0");
	std::filesystem::remove_all("gc_test_c1");
	std::filesystem::create_directories("gc_test_c0");
	std::filesystem::create_directories("gc_test_c1");

	sync::test::test_context net_context;
	net_context.add_client(2);

	sync::test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	gc_servers hp{"127.0.0.1", sync::default_key_server_port, sync::default_storage_server_port, packet_transport::default_packet_server_port};
	event_system::single_thread_event_loop loop;

	test_groupchat alice(net_context.client_context(0), loop, groupchat_config{"gc_test_c0"});
	alice.create_account(hp, "alice");
	alice.connect();
	REQUIRE(alice.packet_connected.get_future().wait_for(5s) == std::future_status::ready);

	auto conn0 = alice.load(hp.sync_server());
	conn0->connect().get();

	chat_id cid = conn0->create_chat("room").id();
	{
		auto f = alice.created.get_future();
		REQUIRE(f.wait_for(5s) == std::future_status::ready);
		REQUIRE(f.get() == cid);
	}

	{
		test_groupchat bob(net_context.client_context(1), loop, groupchat_config{"gc_test_c1"});
		bob.create_account(hp, "bob");
		bob.connect();
		REQUIRE(bob.packet_connected.get_future().wait_for(5s) == std::future_status::ready);

		// the invitation travels through the packet server; bob's key is fetched from
		// the key server by alice's request handler
		alice.send_chat_invitation(user{user_id{net_context.key_id(1)}, hp.key_server()}, "join us", cid);

		auto inv = bob.invitation.get_future();
		REQUIRE(inv.wait_for(5s) == std::future_status::ready);

		// join_chat loads the chat connection but does not connect it (the json layer
		// does the same dance); connect it first so the join actually synchronises
		auto conn1 = bob.load(hp.sync_server());
		conn1->connect().get();
		auto info = bob.join_chat(inv.get());
		CHECK(info.cid == cid);
		{
			auto f = bob.joined.get_future();
			REQUIRE(f.wait_for(5s) == std::future_status::ready);
			REQUIRE(f.get() == cid);
		}

		auto& chan0 = conn0->get(cid);
		auto& chan1 = conn1->get(cid);

		chan0.send_message("hello from alice");
		chan1.send_message("hello from bob");

		WAIT_CHECK(alice.has_message("hello from bob"), 5s);
		WAIT_CHECK(bob.has_message("hello from alice"), 5s);
		WAIT_CHECK(chan0.messages().size() == 2, 5s);
		WAIT_CHECK(chan1.messages().size() == 2, 5s);
	}

	// bob reloads from disk: the channel and both messages are still there
	{
		test_groupchat bob(net_context.client_context(1), loop, groupchat_config{"gc_test_c1"});
		REQUIRE(bob.account_info());
		CHECK(bob.account_info()->name == "bob");
		auto ids = bob.load_channels();
		REQUIRE(ids.size() == 1);
		CHECK(ids.front().cid == cid);
		auto conn1 = bob.load(hp.sync_server());
		CHECK(conn1->get(cid).messages().size() == 2);
	}
}


// (plan 5.5) an invitation names the chat's first block; a join whose block does not
// match what the server serves fails instead of taking the other history
TEST_CASE("groupchat join refuses another history than the invited one", "[system]") {
	std::filesystem::remove_all("gc_test_c0");
	std::filesystem::remove_all("gc_test_c1");
	std::filesystem::create_directories("gc_test_c0");
	std::filesystem::create_directories("gc_test_c1");

	sync::test::test_context net_context;
	net_context.add_client(2);
	sync::test::test_server server(net_context.server_context());
	server.run();

	gc_servers hp{"127.0.0.1", sync::default_key_server_port, sync::default_storage_server_port, packet_transport::default_packet_server_port};
	event_system::single_thread_event_loop loop;

	test_groupchat alice(net_context.client_context(0), loop, groupchat_config{"gc_test_c0"});
	alice.create_account(hp, "alice");
	auto conn0 = alice.load(hp.sync_server());
	conn0->connect().get();
	chat_id cid = conn0->create_chat("room").id();
	REQUIRE(alice.created.get_future().wait_for(5s) == std::future_status::ready);

	// what alice would send, with the first block's hash changed on the way
	auto info = conn0->get(cid).storage_info();
	REQUIRE(info.chain_id.sequence == sync::sequence_number{1});
	info.chain_id.hash = securepath::test::random_octet_vector(64);

	test_groupchat bob(net_context.client_context(1), loop, groupchat_config{"gc_test_c1"});
	bob.create_account(hp, "bob");
	auto conn1 = bob.load(hp.sync_server());
	conn1->connect().get();
	conn1->join(info, "room");
	auto joined = bob.joined.get_future();
	REQUIRE(joined.wait_for(5s) == std::future_status::ready);
	CHECK_THROWS(joined.get());
	CHECK(conn1->get(cid).messages().empty());
}


// (shared_files.txt SF 1) a file shared with the chat is listed by every member and fetched
// on demand; the sharer sees its state, a fetched copy reads back, a removed copy stays listed
TEST_CASE("groupchat shared files", "[system]") {
	chat_pair room;
	auto& chan0 = room.conn0->get(room.cid);
	auto& chan1 = room.conn1->get(room.cid);
	auto const path = std::filesystem::path{"gc_test_c0"} / "shared.bin";
	auto const digest = write_random_file(path, 300000);

	// alice shares: pending until the server took the record, sharing until the data is up
	auto const shared = chan0.share_file(path, "shared.bin", "application/octet-stream");
	CHECK(shared.state == file_state::pending);
	CHECK(shared.size == 300000);
	CHECK(shared.sharer == user_id{room.net_context.key_id(0)});
	WAIT_REQUIRE((chan0.file(shared.id) && chan0.file(shared.id)->state == file_state::shared), 20s);
	WAIT_CHECK(room.alice->files >= 2, 5s);
	WAIT_CHECK(room.alice->saw_file_state(file_state::shared), 5s);

	// bob lists it, on the server until asked for
	WAIT_REQUIRE(chan1.files().size() == 1, 10s);
	auto const listed = chan1.files().front();
	CHECK(listed.id == shared.id);
	CHECK(listed.name == "shared.bin");
	CHECK(listed.mime == "application/octet-stream");
	CHECK(listed.size == 300000);
	CHECK(listed.sharer == user_id{room.net_context.key_id(0)});
	CHECK(listed.state == file_state::on_server);
	WAIT_CHECK(room.bob->files == 1, 5s);
	CHECK_THROWS(chan1.save_file(listed.id, std::filesystem::path{"gc_test_c1"} / "early.bin"));

	// fetched on demand and read back as shared
	chan1.fetch_file(listed.id);
	WAIT_REQUIRE(chan1.file(listed.id)->state == file_state::fetched, 30s);
	WAIT_CHECK(room.bob->saw_file_state(file_state::fetched), 5s);
	auto const out = std::filesystem::path{"gc_test_c1"} / "got.bin";
	chan1.save_file(listed.id, out);
	CHECK(file_digest(out) == digest);

	// the local copy goes, the share stays - a reload lists it still
	chan1.remove_file(listed.id);
	CHECK(chan1.file(listed.id)->state == file_state::removed);
	CHECK(room.bob->file_errors == 0);
	room.conn1.reset();
	room.bob.reset();
	test_groupchat again(room.net_context.client_context(1), room.loop, groupchat_config{"gc_test_c1"});
	REQUIRE(again.load_channels().size() == 1);
	auto conn = again.load(room.hp.sync_server());
	auto const files = conn->get(room.cid).files();
	REQUIRE(files.size() == 1);
	CHECK(files.front().name == "shared.bin");
	CHECK(files.front().state == file_state::removed);
}

}