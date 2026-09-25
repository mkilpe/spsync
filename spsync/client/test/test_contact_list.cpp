// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/contact_list.hpp>
#include <spsync/test/util.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <string>

namespace securepath::sync::client::test {
namespace {

/// add the contact and name it
void add_named(contact_list& list, crypto::public_key_id const& id, std::string const& name) {
	auto c = list.add(id);
	REQUIRE(c);
	CHECK(c->id() == id);
	c->set_name(name);
	CHECK(c->name() == name);
}

/// the list finds the contact under its name
void check_found(contact_list const& list, crypto::public_key_id const& id, std::string const& name) {
	auto c = list.find(id);
	REQUIRE(c);
	CHECK(c->id() == id);
	CHECK(c->name() == name);
}

}

TEST_CASE("contact_list test", "[unit]") {
	contact_list list(sync::test::create_test_database("test_client_list.db"));

	crypto::public_key_id t1{to_octet_vector("test1")};
	crypto::public_key_id t2{to_octet_vector("test2")};

	CHECK(list.enumerate().size() == 0);
	CHECK(!list.find(t1));

	add_named(list, t1, "test");
	check_found(list, t1, "test");
	{
		auto ccs = list.enumerate();
		REQUIRE(ccs.size() == 1);
		auto& c = ccs.front();
		CHECK(c->id() == t1);
		CHECK(c->name() == "test");
	}
	add_named(list, t2, "other");
	check_found(list, t1, "test");
	check_found(list, t2, "other");
	CHECK(list.enumerate().size() == 2);
	list.remove(t1);
	CHECK(!list.find(t1));
	check_found(list, t2, "other");
}

}
