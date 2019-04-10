#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <spsync/util/object_id.hpp>

namespace securepath::sync::util {

TEST_CASE("object_id", "[unit]") {
	object_id empty_id;

	CHECK(test::check_serialisation(empty_id));

	CHECK(!empty_id.is_valid());
	CHECK(empty_id.value().empty());
	CHECK(empty_id.to_hex().empty());

	object_id random_id = create_object_id();

	CHECK(test::check_serialisation(random_id));
	CHECK(random_id.is_valid());
	CHECK(!random_id.value().empty());
	CHECK(!random_id.to_hex().empty());

	CHECK(empty_id != random_id);
	CHECK(random_id == random_id);
	CHECK(empty_id < random_id);
	CHECK(!(random_id < empty_id));

	object_id another_id = create_object_id();
	CHECK(another_id != random_id);
}

}
