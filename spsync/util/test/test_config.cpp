#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <securepath/event_system/asio_broadcast_observer.hpp>

#include <spsync/test/test_context.hpp>
#include <spsync/test/util.hpp>
#include <spsync/util/config.hpp>

namespace securepath::sync::util {

TEST_CASE("config test", "[unit]") {
	test::test_context context;
	context.add_client(1);
	config cfg(test::create_test_database("config_test.db"), "config");

	event_system::asio_broadcast_observer o(cfg.change_notification(), context.client_context(0).io_context());
	std::atomic<int> counter(0);

	o.connect<events::on_config_changed>( [&](auto s)
		{
			LOG_TRACE("event: {}", s);
			++counter;
		} );

	CHECK(!cfg.find(""));
	CHECK(!cfg.find("test"));
	CHECK(!cfg.find("test.some"));

	cfg.set("test", 1);
	CHECK(cfg.find("test"));
	CHECK(cfg.get("test") == 1);
	CHECK(cfg.get_default("test", 2) == 1);
	WAIT_CHECK(counter == 1, 1s);
	counter = 0;

	cfg.remove("test");
	CHECK(!cfg.find("test"));
	CHECK_THROWS(cfg.get("test"));
	CHECK(cfg.get_default("test", 2) == 2);
	WAIT_CHECK(counter == 1, 1s);
	counter = 0;

	cfg.set("test", 1);
	// don't overwrite 'test.'
	CHECK_THROWS(cfg.set("test.some", 1));

	// overwrite it
	cfg.set("test.some", json::value{"ggg"}, false);
	CHECK(cfg.find("test.some"));
	CHECK(cfg.get("test.some") == json::value{"ggg"});
	CHECK(cfg.get("test").is_object());

	cfg.set("test.other.1.2.3", 1);
	CHECK(cfg.get("test.other.1.2.3") == 1);
	cfg.set("test.other.2.2.3", 1);
	CHECK(cfg.get("test.other.1.2.3") == 1);
	CHECK(cfg.get("test.other.2.2.3") == 1);
	WAIT_CHECK(counter == 4, 1s);
	counter = 0;

	cfg.remove("test.other");
	CHECK(!cfg.find("test.other.1.2.3"));
	CHECK(!cfg.find("test.other.2.2.3"));
	CHECK(!cfg.find("test.other.2"));
	CHECK(!cfg.find("test.other"));
	// only the leaf nodes are notified
	WAIT_CHECK(counter == 2, 1s);
	counter = 0;

	cfg.set("gg.1", json::object{{"1", 1}, {"2", json::object{{"a", "test"}}}});
	CHECK(cfg.get("gg.1.1") == 1);
	CHECK(cfg.get("gg.1.2.a") == "test");

	{
		config c(test::create_test_database("config_test.db"), "otherconfig");
		c.set("1.1", "test");
		CHECK(c.get("1.1") == "test");
	}
	{
		config c(test::create_test_database("config_test.db", false), "otherconfig");
		CHECK(c.get("1.1") == "test");
	}
	{
		config c;
		c.set("1.1", "test");
		c.set("1.2", "test");
		CHECK(c.get("1.1") == "test");
		CHECK(c.get("1.2") == "test");
		c.set_database(test::create_test_database("config_test.db"), "ss");
		CHECK(c.get("1.1") == "test");
		CHECK(c.get("1.2") == "test");
	}
	{
		config c;
		c.set("1.1", "other");
		CHECK(c.get("1.1") == "other");
		c.set_database(test::create_test_database("config_test.db", false), "ss");
		CHECK(c.get("1.1") == "other");
		CHECK(c.get("1.2") == "test");
	}
}

}
