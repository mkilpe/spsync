#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/async_key_query.hpp>
#include <spsync/client/events.hpp>

#include <spsync/test/util.hpp>
#include <spsync/test/test_context.hpp>
#include <spsync/test/test_progress.hpp>
#include <spsync/test/test_server_runner.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>

#include <infrastructure/key_server/server_lib/key_server.hpp>

#include <chrono>
#include <vector>

namespace securepath::sync::client::test {

namespace {
struct result {
	error err;
	std::optional<crypto::public_key> key;
	std::any userdata;
};

struct query_test_client : event_system::event_handler {

	query_test_client(network::context& c, event_system::event_loop& loop)
	: event_handler(loop)
	, context(c)
	, query_client(c, *this)
	{}

	~query_test_client() {
		stop_handler();
	}

	void query(user u) {
		query_client.query(u, u.id().public_key_id());
	}

	void on_query(error err, std::optional<crypto::public_key> key, std::any userdata) {
		std::unique_lock l{mutex};
		results.push_back(result{err, key, userdata});
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) {
		dispatch( *ev
			, event_dest<query_event>(&query_test_client::on_query) );
	}

	std::size_t results_size() const {
		std::unique_lock l{mutex};
		return results.size();
	}

	void clear() {
		results.clear();
	}

	bool check(std::size_t i, bool has_error, crypto::public_key_id id, crypto::public_key_access const& keys) const {
		std::unique_lock l{mutex};
		auto key = keys.find(id);
		REQUIRE(!results.empty());
		CAPTURE(has_error, results[i].err, id);
		if(results[i].key) {
			CAPTURE(*results[i].key);
		}
		if(key) {
			CAPTURE(*key);
		}
		bool ret = static_cast<bool>(results[i].err) == has_error;
		CHECK(static_cast<bool>(results[i].err) == has_error);
		if(has_error) {
			ret &= !results[i].key;
			CHECK(!results[i].key);
		} else {
			ret &= bool(results[i].key) == bool(key);
			REQUIRE(bool(results[i].key) == bool(key));
			ret &= !key || *key == *results[i].key;
			CHECK((!key || *key == *results[i].key));
		}
		ret &= std::any_cast<crypto::public_key_id>(results[i].userdata) == id;
		CHECK(std::any_cast<crypto::public_key_id>(results[i].userdata) == id);
		return ret;
	}

	mutable std::mutex mutex;
	network::context& context;
	std::deque<result> results;
	async_key_query query_client;
};

/// the queries in order; every one answered as expected, with the key the cache holds
void check_queries(query_test_client& c, std::vector<user> const& queries, bool has_error
	, crypto::public_key_access const& keys, std::chrono::seconds wait) {
	c.clear();
	for(auto const& u : queries) {
		c.query(u);
	}
	WAIT_REQUIRE(c.results_size() == queries.size(), wait);
	for(std::size_t i = 0; i != queries.size(); ++i) {
		CHECK(c.check(i, has_error, queries[i].id().public_key_id(), keys));
	}
}

/// the context with its clients and their keys known to the server
sync::test::test_context& with_clients(sync::test::test_context& ctx, int count) {
	ctx.add_client(count);
	ctx.add_client_keys_for_server();
	return ctx;
}

/// a test server with its key server and a second key server on another port, both
/// running; the key cache holds both servers' public keys
struct two_key_servers {
	two_key_servers()
	: server(with_clients(net_context, 4).server_context())
	, secondary_key_server(with_clients(secondary_net_context, 2).server_context()
		, key_server::server_params{.port=key_server::default_key_server_port+10})
	{
		server.run();
		secondary_key_server.run();
		keys.add_backend(std::shared_ptr<crypto::public_key_access>(&net_context.server_context().public_keys(), [](auto){}));
		keys.add_backend(std::shared_ptr<crypto::public_key_access>(&secondary_net_context.server_context().public_keys(), [](auto){}));
	}

	/// the user of the primary context's key at the primary key server
	user primary(std::size_t i) const {
		return user{net_context.key_id(i), local};
	}

	/// the user of the secondary context's key at the secondary key server
	user secondary(std::size_t i) const {
		return user{secondary_net_context.key_id(i), slocal};
	}

public:
	event_system::single_thread_event_loop single_thread_event_loop;
	sync::test::test_context net_context;
	sync::test::test_context secondary_net_context{net_context.root_key()};
	sync::test::test_server server;
	key_server::server secondary_key_server;
	host_port local{"127.0.0.1", sync::default_key_server_port};
	host_port bad_local{"127.0.0.1", sync::default_key_server_port+1};
	host_port slocal{"127.0.0.1", sync::default_key_server_port+10};
	crypto::public_key_cache keys;
};
}

TEST_CASE("async key query test", "[unit]") {
	two_key_servers f;
	auto temp_key = crypto::generate_private_key();
	crypto::public_key_id non_existent_id = temp_key.id();
	query_test_client c(f.net_context.client_context(0), f.single_thread_event_loop);

	check_queries(c, {f.primary(0)}, false, f.keys, 2s);

	std::vector<user> four;
	for(int i = 0; i != 4; ++i) {
		four.push_back(f.primary(i));
	}
	check_queries(c, four, false, f.keys, 4s);

	check_queries(c, {user{non_existent_id, f.local}}, false, f.keys, 2s);
	check_queries(c, {user{f.net_context.key_id(0), f.bad_local}}, true, f.keys, 2s);

	std::vector<user> hundred;
	for(int i = 0; i != 100; ++i) {
		hundred.push_back(f.primary(i%4));
	}
	check_queries(c, hundred, false, f.keys, 20s);

	check_queries(c, {f.primary(0), f.secondary(0), f.primary(1), f.secondary(1)}, false, f.keys, 6s);

	// let it destruct while having queries in progress
	for(int i = 0; i != 100; ++i) {
		c.query(f.primary(i%4));
	}
}

}
