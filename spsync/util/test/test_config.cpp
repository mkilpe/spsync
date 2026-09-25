// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <securepath/event_system/event_handler_helpers.hpp>
#include <securepath/event_system/event_loop.hpp>

#include <spsync/test/util.hpp>
#include <spsync/util/config.hpp>

#include <atomic>

namespace securepath::sync::util {
namespace {

/// counts the change events delivered through the loop
struct change_counter : event_system::event_handler {
	using event_handler::event_handler;
	~change_counter() { stop_handler(); }

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch(*ev, event_dest<events::on_config_changed>([this](std::string const& key) {
				LOG_TRACE("event: {}", key);
				++counter;
			}));
	}

	std::atomic<int> counter{0};
};

/// a value set, read and removed: one change event each way
void check_set_and_remove(config& cfg, std::atomic<int>& counter) {
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
}

/// nested keys: a leaf turns into a node only when said so, a removed node notifies its
/// leaves, an object sets its leaves
void check_nested_keys(config& cfg, std::atomic<int>& counter) {
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
}

/// a config of another name in the database, read back by another connection
void check_persisted_config() {
	{
		config c(test::create_test_database("config_test.db"), "otherconfig");
		c.set("1.1", "test");
		CHECK(c.get("1.1") == "test");
	}
	{
		config c(test::create_test_database("config_test.db", false), "otherconfig");
		CHECK(c.get("1.1") == "test");
	}
}

/// values set before the database is there go into it, values in it are read
void check_late_database() {
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

TEST_CASE("config test", "[unit]") {
	event_system::single_thread_event_loop loop;
	change_counter o{loop};
	auto& counter = o.counter;
	config cfg(test::create_test_database("config_test.db"), "config", &o);

	check_set_and_remove(cfg, counter);
	check_nested_keys(cfg, counter);
	check_persisted_config();
	check_late_database();
}

}
