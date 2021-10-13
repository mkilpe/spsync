#include <groupchat/core/message_storage.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>


namespace securepath::groupchat::test {

static message_id new_message_id() {
	return message_id{securepath::test::random_octet_vector(8)};
}

TEST_CASE("message_storage test", "[unit]") {
	std::remove("message_storage.db");
	message_storage s(database::sqlite::create_sqlite_connection("message_storage.db"));

	CHECK(s.get(message_search{}).empty());

	msg_change c = s.insert(new_message_id(), message_data{"1"}, msg_state::in_sync);
	CHECK(c.new_index == 1);
	CHECK(c.old_index == 0);
	CHECK(c.state == msg_state::in_sync);
	{
		auto list = s.get(message_search{});
		REQUIRE(list.size() == 1);
		CHECK(list[0].data == "1");
		CHECK(list[0].index == 1);
	}
	{
		auto list = s.get(message_search{0,0,msg_order::index_ascending});
		REQUIRE(list.size() == 1);
		CHECK(list[0].data == "1");
		CHECK(list[0].index == 1);
	}
	auto pid = new_message_id();
	c = s.insert(pid, message_data{"2"}, msg_state::pending);
	CHECK(c.new_index == 2);
	CHECK(c.old_index == 0);
	CHECK(c.id == pid);
	CHECK(c.state == msg_state::pending);
	{
		auto list = s.get(message_search{});
		REQUIRE(list.size() == 2);
		CHECK(list[0].data == "2");
		CHECK(list[0].index == 2);
		CHECK(list[0].state == msg_state::pending);
		CHECK(list[1].data == "1");
		CHECK(list[1].index == 1);
		CHECK(list[1].state == msg_state::in_sync);
	}
	{
		auto list = s.get(message_search{0,0,msg_order::index_ascending});
		REQUIRE(list.size() == 2);
		CHECK(list[0].data == "1");
		CHECK(list[0].index == 1);
		CHECK(list[0].state == msg_state::in_sync);
		CHECK(list[1].data == "2");
		CHECK(list[1].index == 2);
		CHECK(list[1].state == msg_state::pending);
	}
	{
		auto list = s.get(message_search{0, 1});
		REQUIRE(list.size() == 1);
		CHECK(list[0].data == "2");
		CHECK(list[0].index == 2);
	}
	{
		auto list = s.get(message_search{0,1,msg_order::index_ascending});
		REQUIRE(list.size() == 1);
		CHECK(list[0].data == "1");
		CHECK(list[0].index == 1);
	}
	c = s.insert(pid, message_data{"2"}, msg_state::in_sync);
	CHECK(c.new_index == 2);
	CHECK(c.old_index == 2);
	CHECK(c.id == pid);
	CHECK(c.state == msg_state::in_sync);
	{
		auto list = s.get(message_search{});
		REQUIRE(list.size() == 2);
		CHECK(list[0].data == "2");
		CHECK(list[0].index == 2);
		CHECK(list[0].state == msg_state::in_sync);
		CHECK(list[1].data == "1");
		CHECK(list[1].index == 1);
		CHECK(list[1].state == msg_state::in_sync);
	}
	for(int i = 3; i != 100; ++i) {
		s.insert(new_message_id(), message_data{std::to_string(i)}, msg_state::in_sync);
	}
	for(int i = 100; i != 107; ++i) {
		s.insert(new_message_id(), message_data{std::to_string(i)}, msg_state::pending);
	}
	{
		auto list = s.get(message_search{});
		REQUIRE(list.size() == 106);
		CHECK(list[0].data == "106");
		CHECK(list[0].index == 106);
	}
	SECTION("chunk") {
		int chuck_size = GENERATE(1,2,3,7,12,23,30);
		int total_amount = 106;
		while(total_amount > 0) {
			auto list = s.get(message_search{total_amount, std::size_t(chuck_size)});
			REQUIRE(list.size() <= total_amount);
			REQUIRE((list.size() == total_amount || list.size() == chuck_size));
			for(int i = 0; i != list.size(); ++i) {
				auto v = total_amount-i;
				REQUIRE(list[i].data == std::to_string(v));
				REQUIRE(list[i].index == v);
			}
			total_amount -= list.size();
		}
	}

	// mark one of the pending ones as synced and try again
	auto list = s.get(message_search{0, 5});
	c = s.insert(list[4].mid, message_data{list[4].data}, msg_state::in_sync);
	CHECK(c.new_index == 100);
	CHECK(c.old_index == list[4].index);
	CHECK(c.id == list[4].mid);
	CHECK(c.state == msg_state::in_sync);
	SECTION("chunk2") {
		int chuck_size = GENERATE(1,2,3,12,30);
		int total_amount = 106;
		while(total_amount > 0) {
			auto list = s.get(message_search{total_amount, std::size_t(chuck_size)});
			REQUIRE(list.size() <= total_amount);
			REQUIRE((list.size() == total_amount || list.size() == chuck_size));
			for(int i = 0; i != list.size(); ++i) {
				auto v = total_amount-i;
				REQUIRE(list[i].index == v);
			}
			total_amount -= list.size();
		}
	}
}

}