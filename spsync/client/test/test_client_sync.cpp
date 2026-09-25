#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/client_sync.hpp>
#include <spsync/client/record_util.hpp>
#include <spsync/core/data/source_record_data.hpp>

#include <spsync/test/util.hpp>
#include <spsync/test/test_context.hpp>
#include <spsync/test/test_progress.hpp>
#include <spsync/test/test_server_runner.hpp>

#include <securepath/crypto/private_data_access.hpp>

#include <filesystem>
#include <future>
#include <memory>
#include <string>
#include <vector>

namespace securepath::sync::client::test {
namespace {
/// the connection outlives the client_sync (which detaches from it on destruction)
struct test_net {
	test_net(network::context& context, event_system::event_handler& handler)
	: net(context, handler)
	{}
	network_connection net;
};

class test_client : public event_system::event_handler, public test_net, public client_sync {
public:
	test_client(event_system::event_loop& loop, network::context& context, std::string const& dbname, sync_engine_config config = {})
	: event_handler(loop)
	, test_net(context, *this)
	, client_sync(context, loop, sync::test::create_test_database(dbname), std::move(config))
	{}

	~test_client() {
		client_sync::stop_handler();
		event_handler::stop_handler();
	}

	void connect() {
		net.connect("127.0.0.1", default_storage_server_port);
	}

	void disconnect() {
		net.close();
	}

	storage_id create_remote_storage() {
		return net.create_storage();
	}

	void connect_to_storage(storage_id const& sid) {
		assert(!sid.empty());

		//after this the events will be received
		init(sid, net);
	}

	void wait_for_connection() {
		connected_.get_future().get();
	}

	void on_connect() {
		try {
			connected_.set_value();
		} catch(...) {}
	}

	void on_disconnect(error const& err) {
		try {
			connected_.set_exception(std::make_exception_ptr(err));
		} catch(...) {}
	}

	void on_create_storage(storage_id const& sid, error const& err) {
		if(err) {
			storage_created_.set_exception(std::make_exception_ptr(err));
		} else {
			connect_to_storage(sid);
			storage_created_.set_value();
		}
	}

	void wait_for_storage_created() {
		storage_created_.get_future().get();
	}

	void handle_event(std::unique_ptr<event_base> ev) override {
		dispatch( *ev
				, event_dest<events::on_connect>(&test_client::on_connect)
				, event_dest<events::on_disconnect>(&test_client::on_disconnect)
				, event_dest<events::on_create_storage>(&test_client::on_create_storage) );
	}


	void on_data_change(record_handle rec, std::deque<single_data_change> c) override {
		std::unique_lock l{mutex};
		d_changes.insert(d_changes.end(), c.begin(), c.end());
		d_records.push_back(std::move(rec));
	}

	std::deque<record_handle> data_records() const {
		std::unique_lock l{mutex};
		return d_records;
	}

	void on_user_change(record_handle, user_change c) override {
		std::unique_lock l{mutex};
		u_changes.push_back(c);
	}

	void on_data_state_changed(data_id id, record_data_state state) override {
		std::unique_lock l{mutex};
		data_states.emplace_back(std::move(id), state);
	}

	std::size_t data_state_count() const {
		std::unique_lock l{mutex};
		return data_states.size();
	}

	void on_data_transfer_failed(data_id id, error) override {
		std::unique_lock l{mutex};
		failed_transfers.push_back(std::move(id));
	}

	std::size_t failed_transfer_count() const {
		std::unique_lock l{mutex};
		return failed_transfers.size();
	}

	std::deque<single_data_change> data_changes() const {
		std::unique_lock l{mutex};
		return d_changes;
	}

	std::deque<user_change> user_changes() const {
		std::unique_lock l{mutex};
		return u_changes;
	}

public:
	mutable std::mutex mutex;
	std::deque<single_data_change> d_changes;
	std::deque<record_handle> d_records;
	std::deque<user_change> u_changes;
	std::deque<data_id> failed_transfers;
	std::deque<std::pair<data_id, record_data_state>> data_states;

private:
	std::promise<void> connected_;
	std::promise<void> storage_created_;
};

bool check_member_status(test_client const& c, crypto::public_key_id const& uid, member_status status) {
	auto m = c.find_member(util::user_id{uid});
	REQUIRE(m);
	CHECK(m->status() == status);
	return m->status() == status;
}

/// the client's members are exactly these keys of the context, each with its status
void check_members(test_client const& c, sync::test::test_context const& ctx
	, std::vector<std::pair<int, member_status>> const& expected) {
	CHECK(c.members().size() == expected.size());
	for(auto const& [i, status] : expected) {
		CHECK(check_member_status(c, ctx.key_id(i), status));
	}
}

/// the content read back whole from a data handle
bool reads_content(record_data& data, octet_vector const& content) {
	octet_vector read_back(content.size());
	return data.read(0, read_back.data(), read_back.size()) == content.size() && read_back == content;
}

/// a server with a data role under the root; the record role names it to the clients
spsync_server_params data_role_params(std::string const& root, data_endpoint const& data_server) {
	spsync_server_params params;
	params.storage_params.storage_root = root;
	params.storage_params.data_servers = {data_server};
	params.data_params.enabled = true;
	params.data_params.storage_root = root;
	return params;
}

/// the data role holds the data under the storage, the record role knows who does
void check_held_by(sync::test::test_server& server, storage_id const& sid, data_id const& id, crypto::public_key_id const& holder) {
	auto const held = server.data().find(sid, id);
	REQUIRE(held);
	CHECK(held->state == record_data_state::in_sync);
	auto const holdings = server.storages().availability().holdings(sid, id);
	REQUIRE(holdings.size() == 1);
	CHECK(holdings[0].holder == holder);
	CHECK(holdings[0].complete);
}

/// the member holds nothing of its only data record until it asks; then it has the content
void check_lazy_fetch(test_client& c, octet_vector const& content) {
	auto lazy = c.object_data(c.data_records().front());
	REQUIRE(lazy);
	CHECK(lazy->state() == record_data_state::deferred);
	CHECK(lazy->available_size() == 0);
	auto fetched = c.fetch_object_data(c.data_records().front());
	REQUIRE(fetched);
	WAIT_CHECK(fetched->state() == record_data_state::in_sync, 20s);
	CHECK(reads_content(*fetched, content));
	CHECK(c.failed_transfer_count() == 0);
}

/**
 * Clients of one storage over a test server: the context knows every client's key, the
 * first client creates the storage and the others join it, and the first user change
 * makes members of them all.
 */
struct sync_clients {
	explicit sync_clients(int client_count) {
		net_context.add_client(client_count);
		net_context.add_client_keys_for_server();
		net_context.share_client_keys();
	}

	/// the server over the context, listening when this returns
	void run_server(spsync_server_params params = {}) {
		server = std::make_unique<sync::test::test_server>(net_context.server_context(), params);
		server->run();
	}

	/// a client over the context of the index, with its own database
	test_client& add_client(std::size_t index, std::string const& dbname, sync_engine_config config = {}) {
		clients.push_back(std::make_unique<test_client>(loop, net_context.client_context(index), dbname, std::move(config)));
		return *clients.back();
	}

	/// the first client creates the storage, every other one joins it
	storage_id connect_all() {
		for(auto& c : clients) {
			c->connect();
		}
		auto& first = *clients.front();
		first.wait_for_connection();
		auto const sid = first.create_remote_storage();
		first.wait_for_storage_created();
		for(std::size_t i = 1; i != clients.size(); ++i) {
			clients[i]->wait_for_connection();
			clients[i]->connect_to_storage(sid);
		}
		return sid;
	}

	/// the first client makes every client a member; all of them see the change
	void make_members() {
		users us(users_change_mode::full);
		for(std::size_t i = 0; i != clients.size(); ++i) {
			us.add(util::user_access{net_context.key_id(i), util::access_type::user_management_access});
		}
		clients.front()->send_user_change(us);
		for(auto& c : clients) {
			WAIT_CHECK(c->user_changes().size() == 1, 2s);
		}
	}

public:
	event_system::single_thread_event_loop loop;
	sync::test::test_context net_context;
	std::unique_ptr<sync::test::test_server> server;
	std::vector<std::unique_ptr<test_client>> clients;
};

/// three clients with data roots of their own, the third fetching small data unasked
void add_upload_clients(sync_clients& f) {
	for(int i = 0; i != 3; ++i) {
		auto const name = "client_sync_upload_c" + std::to_string(i + 1);
		std::filesystem::remove_all(name);
		sync_engine_config config;
		config.data_root = name;
		// the third member fetches what is small enough unasked
		config.auto_fetch_max_size = i == 2 ? 16 * 1024 * 1024 : 0;
		f.add_client(i, name + ".db", config);
	}
}
}

TEST_CASE("client_sync", "[unit]") {
	using enum member_status;
	sync_clients f{4};
	f.run_server();
	auto& c1 = f.add_client(0, "client_sync_c1.db");
	auto& c2 = f.add_client(1, "client_sync_c2.db");
	f.connect_all();
	f.make_members();

	// check initial members
	check_members(c1, f.net_context, {{0, member}, {1, member}});
	check_members(c2, f.net_context, {{0, member}, {1, member}});

	// add members
	c1.add_member(util::user_id{f.net_context.key_id(2)});
	c2.add_member(util::user_id{f.net_context.key_id(3)});
	WAIT_CHECK(c1.user_changes().size() == 3, 2s);
	check_members(c1, f.net_context, {{0, member}, {1, member}, {2, member}, {3, member}});
	WAIT_CHECK(c2.user_changes().size() == 3, 2s);
	check_members(c2, f.net_context, {{0, member}, {1, member}, {2, member}, {3, member}});

	// remove members
	c1.remove_member(util::user_id{f.net_context.key_id(2)});
	c2.remove_member(util::user_id{f.net_context.key_id(3)});
	WAIT_CHECK(c1.user_changes().size() == 5, 2s);
	check_members(c1, f.net_context, {{0, member}, {1, member}});
	WAIT_CHECK(c2.user_changes().size() == 5, 2s);
	check_members(c2, f.net_context, {{0, member}, {1, member}});

	// pending add members
	c1.disconnect();
	c1.add_member(util::user_id{f.net_context.key_id(2)});
	check_members(c1, f.net_context, {{0, member}, {1, member}, {2, pending_add}});

	// pending remove members
	c2.disconnect();
	c2.remove_member(util::user_id{f.net_context.key_id(1)});
	check_members(c2, f.net_context, {{0, member}, {1, pending_remove}});

	c1.connect();
	c2.connect();
	WAIT_CHECK(c1.user_changes().size() == 7, 2s);
	check_members(c1, f.net_context, {{0, member}, {2, member}});
	WAIT_CHECK(c2.user_changes().size() == 7, 2s);
	check_members(c2, f.net_context, {{0, member}, {2, member}});
}

// (RDS 3) the record side of record data over a real server that has no data servers:
// the change commits with its descriptor, the author holds the data (upload_pending, the
// ticket is refused), the other member sees what it would have to fetch
TEST_CASE("client_sync data change with record data", "[unit]") {
	sync_clients f{2};
	f.run_server();
	std::filesystem::remove_all("client_sync_data_c1");
	std::filesystem::remove_all("client_sync_data_c2");
	sync_engine_config config1;
	config1.data_root = "client_sync_data_c1";
	sync_engine_config config2;
	config2.data_root = "client_sync_data_c2";
	auto& c1 = f.add_client(0, "client_sync_data_c1.db", config1);
	auto& c2 = f.add_client(1, "client_sync_data_c2.db", config2);
	f.connect_all();
	f.make_members();

	auto const content = securepath::test::random_octet_vector(300000);
	auto sent = c1.send_data_change(util::create_object_id(), util::metadata{}, std::make_shared<memory_record_data>(content));
	REQUIRE(sent);

	WAIT_CHECK(c1.data_changes().size() == 1, 2s);
	WAIT_CHECK(c2.data_changes().size() == 1, 2s);
	CHECK(sent->state() == record_state::in_sync);

	// the author: everything held, the upload refused - the server names no data servers
	WAIT_CHECK(c1.failed_transfer_count() == 1, 2s);
	auto own = c1.object_data(sent);
	REQUIRE(own);
	CHECK(own->state() == record_data_state::upload_pending);
	CHECK(reads_content(*own, content));

	// the other member: both descriptor halves arrived, nothing is held
	REQUIRE(c2.data_changes().size() == 1);
	auto const change = c2.data_changes().front();
	REQUIRE(change.data.data);
	REQUIRE(change.header.data_info());
	CHECK(change.header.data_info()->plain_size == content.size());
	CHECK(c1.failed_transfers.front() == change.data.data->manifest_digest);

	auto remote = c2.object_data(c2.data_records().front());
	REQUIRE(remote);
	CHECK(remote->state() == record_data_state::deferred);
	CHECK(remote->size() == content.size());
	CHECK(remote->available_size() == 0);
	octet_vector read_back(content.size());
	CHECK(remote->read(0, read_back.data(), read_back.size()) == 0);
	CHECK(c2.failed_transfer_count() == 0);
}

// (RDS 5/6) record data end to end over an all-in-one server: the author's engine asks
// for the upload once the record is confirmed, comm gets the ticket from the record role
// and moves the chunks to the data role, the data becomes in_sync, the record role's
// availability table knows the holder and the clients persist the data server list.
// Another member fetches the data when it asks for it (lazy), a third one as soon as the
// record arrives (auto fetch) - when that is before the upload has landed it is
// remote_not_complete until the server's notify_data brings it back
TEST_CASE("client_sync transfers record data", "[unit]") {
	sync_clients f{3};
	std::filesystem::remove_all("client_sync_upload_root");
	auto const server_key = crypto::my_private_key(f.net_context.server_context().private_data());
	data_endpoint const data_server{"127.0.0.1", default_data_server_port, server_key.id(), "test", {}};
	f.run_server(data_role_params("client_sync_upload_root", data_server));
	REQUIRE(f.server->data().local_endpoint().has_value());

	add_upload_clients(f);
	auto& c1 = *f.clients[0];
	auto& c2 = *f.clients[1];
	auto& c3 = *f.clients[2];
	auto const sid = f.connect_all();
	f.make_members();

	auto const content = securepath::test::random_octet_vector(3 * 1024 * 1024);
	auto sent = c1.send_data_change(util::create_object_id(), util::metadata{}, std::make_shared<memory_record_data>(content));
	REQUIRE(sent);
	WAIT_CHECK(c1.data_changes().size() == 1, 5s);
	WAIT_CHECK(c2.data_changes().size() == 1, 5s);
	WAIT_CHECK(c3.data_changes().size() == 1, 5s);

	// uploaded
	WAIT_CHECK(c1.data_state_count() == 1, 20s);
	REQUIRE(c1.data_states.size() == 1);
	CHECK(c1.data_states[0].second == record_data_state::in_sync);
	CHECK(c1.failed_transfer_count() == 0);
	auto own = c1.object_data(sent);
	REQUIRE(own);
	CHECK(own->state() == record_data_state::in_sync);

	// the data role holds it under the storage, the record role knows who does
	check_held_by(*f.server, sid, c1.data_states[0].first, server_key.id());

	// lazy: the second member holds nothing until it asks
	check_lazy_fetch(c2, content);

	// auto fetch: the third member has it without asking
	auto automatic = c3.object_data(c3.data_records().front());
	REQUIRE(automatic);
	WAIT_CHECK(automatic->state() == record_data_state::in_sync, 20s);
	CHECK(reads_content(*automatic, content));

	// all of them learned the storage's data servers on attach
	for(int i = 0; i != 3; ++i) {
		record_storage records{sync::test::create_test_database("client_sync_upload_c" + std::to_string(i + 1) + ".db", false)};
		CHECK(records.data_endpoints() == std::vector<data_endpoint>{data_server});
	}
}

}
