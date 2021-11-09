#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/async_key_query.hpp>
#include <spsync/client/events.hpp>

#include <spsync/test/util.hpp>
#include <spsync/test/test_context.hpp>
#include <spsync/test/test_progress.hpp>
#include <spsync/test/test_server_runner.hpp>
#include <securepath/crypto/rsa.hpp>
#include <securepath/crypto/public_key_cache.hpp>

#include <infrastructure/key_server/server_lib/unknown_user_key_server.hpp>

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
}

TEST_CASE("async key query test", "[unit]") {
	event_system::single_thread_event_loop single_thread_event_loop;
	sync::test::test_context net_context;
	sync::test::test_context secondary_net_context(net_context.root_key());

	net_context.add_client(4);
	net_context.add_client_keys_for_server();

	secondary_net_context.add_client(2);
	secondary_net_context.add_client_keys_for_server();

	sync::test::test_server server(net_context.server_context());
	server.run();

	key_server::unknown_user_key_server secondary_key_server(
		secondary_net_context.server_context(),
		key_server::unknown_user_key_server_params{.port=key_server::default_unknown_user_key_server_port+10});

	secondary_key_server.run();

	std::this_thread::sleep_for(1s);

	host_port local{"127.0.0.1", sync::default_key_server_port};
	host_port bad_local{"127.0.0.1", sync::default_key_server_port+1};
	host_port slocal{"127.0.0.1", sync::default_key_server_port+10};
	auto temp_key = crypto::generate_rsa_private_key(1024);
	crypto::public_key_id non_existent_id = temp_key.id();

	// make key cache that contains both server's public keys
	crypto::public_key_cache keys;
	keys.add_backend(std::shared_ptr<crypto::public_key_access>(&net_context.server_context().public_keys(), [](auto){}));
	keys.add_backend(std::shared_ptr<crypto::public_key_access>(&secondary_net_context.server_context().public_keys(), [](auto){}));

	query_test_client c(net_context.client_context(0), single_thread_event_loop);

	{
		c.query(user{net_context.key_id(0), local});
		WAIT_REQUIRE(c.results_size() == 1, 2s);
		CHECK(c.check(0, false, net_context.key_id(0), keys));
	}
	{
		c.clear();
		for(int i = 0; i != 4; ++i) {
			c.query(user{net_context.key_id(i), local});
		}
		WAIT_REQUIRE(c.results_size() == 4, 4s);
		for(int i = 0; i != 4; ++i) {
			CHECK(c.check(i, false, net_context.key_id(i), keys));
		}
	}
	{
		c.clear();
		c.query(user{non_existent_id, local});
		WAIT_REQUIRE(c.results_size() == 1, 2s);
		CHECK(c.check(0, false, non_existent_id, keys));
	}
	{
		c.clear();
		c.query(user{net_context.key_id(0), bad_local});
		WAIT_REQUIRE(c.results_size() == 1, 2s);
		CHECK(c.check(0, true, net_context.key_id(0), keys));
	}
	{
		c.clear();
		for(int i = 0; i != 100; ++i) {
			c.query(user{net_context.key_id(i%4), local});
		}
		WAIT_REQUIRE(c.results_size() == 100, 20s);
		for(int i = 0; i != 100; ++i) {
			CHECK(c.check(i, false, net_context.key_id(i%4), keys));
		}
	}
	{
		c.clear();
		c.query(user{net_context.key_id(0), local});
		c.query(user{secondary_net_context.key_id(0), slocal});
		c.query(user{net_context.key_id(1), local});
		c.query(user{secondary_net_context.key_id(1), slocal});
		WAIT_REQUIRE(c.results_size() == 4, 6s);
		CHECK(c.check(0, false, net_context.key_id(0), keys));
		CHECK(c.check(1, false, secondary_net_context.key_id(0), keys));
		CHECK(c.check(2, false, net_context.key_id(1), keys));
		CHECK(c.check(3, false, secondary_net_context.key_id(1), keys));
	}

	// let it destruct while having queries in progress
	for(int i = 0; i != 100; ++i) {
		c.query(user{net_context.key_id(i%4), local});
	}
}

}