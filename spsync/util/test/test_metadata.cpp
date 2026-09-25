// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <spsync/util/metadata.hpp>

namespace securepath::sync::util {
namespace {
struct test_type {
	std::string data;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & data;
	}
};
}

TEST_CASE("metadata", "[unit]") {
	metadata data;

	CHECK(test::check_serialisation_without_compare(data));

	CHECK(!data.find(""));
	CHECK(!data.find("some"));

	{ //untyped insert and find
		data.insert("test", to_octet_vector("data"));
		auto result = data.find("test");
		REQUIRE(result);
		CHECK(*result == to_octet_vector("data"));
	}

	{ //typed insert and find
		data.insert("key", test_type{"other data"});
		CHECK(data.find("key"));
		auto result = data.find<test_type>("key");
		REQUIRE(result);
		CHECK(result->data == "other data");
	}

	CHECK(test::check_serialisation_without_compare(data));

	{ // replace
		data.insert("key", to_octet_vector("some"));
		auto result = data.find("key");
		REQUIRE(result);
		CHECK(*result == to_octet_vector("some"));
	}

	{ //erase
		data.erase("key");
		CHECK(!data.find("key"));
		CHECK_NOTHROW(data.erase("random")); //no op
	}

	{ //wrong type
		CHECK_THROWS(data.find<test_type>("test"));
	}
}

TEST_CASE("metadata init", "[unit]") {
	{
		CHECK(metadata().empty());
		CHECK(metadata{}.empty());
	}
	{
		metadata data{{"test", to_octet_vector("data")}};
		CHECK(!data.empty());
		auto result = data.find("test");
		REQUIRE(result);
		CHECK(*result == to_octet_vector("data"));
	}
}

}
