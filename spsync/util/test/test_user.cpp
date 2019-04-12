#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <spsync/util/user.hpp>

namespace securepath::sync::util {

TEST_CASE("user_id", "[unit]") {
	user_id empty_id;
	CHECK(test::check_serialisation(empty_id));
	CHECK(!empty_id.is_valid());

	//fake public key id
	crypto::public_key_id key_id{to_octet_vector("test")};
	user_id id{key_id};
	CHECK(id.public_key_id() == key_id);
	CHECK(id != empty_id);

	user_id copy_id{id};
	CHECK(copy_id == id);
	CHECK(!(copy_id < id));

	CHECK(empty_id < id);
}

TEST_CASE("access_type", "[unit]") {
	access_type access = access_type::no_access;
	CHECK(test::check_serialisation(access));
}

}
