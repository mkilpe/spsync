#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/contact_list.hpp>
#include <spsync/test/util.hpp>
#include <securepath/database/sqlite/connection.hpp>

namespace securepath::sync::client::test {

TEST_CASE("contact_list test", "[unit]") {
	contact_list list(sync::test::create_test_database("test_client_list.db"));

	crypto::public_key_id t1{to_octet_vector("test1")};
	crypto::public_key_id t2{to_octet_vector("test2")};

	CHECK(list.enumerate().size() == 0);
	CHECK(!list.find(t1));

	{
		auto c = list.add(t1);
		REQUIRE(c);
		CHECK(c->id() == t1);
		c->set_name("test");
		CHECK(c->name() == "test");
	}
	{
		auto c = list.find(t1);
		REQUIRE(c);
		CHECK(c->id() == t1);
		CHECK(c->name() == "test");
	}
	{
		auto ccs = list.enumerate();
		REQUIRE(ccs.size() == 1);
		auto& c = ccs.front();
		CHECK(c->id() == t1);
		CHECK(c->name() == "test");
	}
	{
		auto c = list.add(t2);
		REQUIRE(c);
		CHECK(c->id() == t2);
		c->set_name("other");
		CHECK(c->name() == "other");
	}
	{
		auto c = list.find(t1);
		REQUIRE(c);
		CHECK(c->id() == t1);
		CHECK(c->name() == "test");
	}
	{
		auto c = list.find(t2);
		REQUIRE(c);
		CHECK(c->id() == t2);
		CHECK(c->name() == "other");
	}
	CHECK(list.enumerate().size() == 2);
	list.remove(t1);
	CHECK(!list.find(t1));
	{
		auto c = list.find(t2);
		REQUIRE(c);
		CHECK(c->id() == t2);
		CHECK(c->name() == "other");
	}
}

}
