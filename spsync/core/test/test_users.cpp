// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/core/users.hpp>

#include <securepath/crypto/random.hpp>

namespace securepath::sync::test {

static util::user_id create_user() {
	return {crypto::public_key_id{crypto::random_octet_vector(8)}};
}

static bool has_user(auto const& container, util::user_id const& user) {
	return std::find_if(container.begin(), container.end(),
		[&](auto v) {
			return v.user == user;
		})
		!= container.end();
}


TEST_CASE("users full", "[unit]") {
	users us{users_change_mode::full};

	auto u1 = create_user();
	auto u2 = create_user();
	auto u3 = create_user();

	CHECK(us.access().empty());

	us.add(util::user_access{u1, util::access_type::data_read_access});
	us.add(util::user_access{u1, util::access_type::user_management_access});
	CHECK(us.access().size() == 1);
	auto it = us.begin();
	CHECK(it != us.end());
	CHECK(it->user == u1);
	CHECK(it->access == util::access_type::user_management_access);

	us.remove(u1);
	CHECK(us.access().empty());

	us.add(util::user_access{u1, util::access_type::user_management_access});
	us.add(util::user_access{u2, util::access_type::user_management_access});
	us.add(util::user_access{u3, util::access_type::user_management_access});
	CHECK(us.access().size() == 3);
	CHECK(has_user(us, u1));
	CHECK(has_user(us, u2));
	CHECK(has_user(us, u3));

	us.remove(u2);
	CHECK(us.access().size() == 2);
	CHECK(has_user(us, u1));
	CHECK(has_user(us, u3));
}

TEST_CASE("users delta", "[unit]") {
	users us{users_change_mode::delta};

	auto u1 = create_user();
	auto u2 = create_user();
	auto u3 = create_user();

	us.add(util::user_access{u1, util::access_type::user_management_access});
	us.remove(u2);

	CHECK(us.access().size() == 2);
	CHECK(has_user(us, u1));
	CHECK(has_user(us, u2));

	us.remove(u1);
	us.add(util::user_access{u2, util::access_type::user_management_access});

	CHECK(us.access().size() == 2);
	CHECK(has_user(us, u1));
	CHECK(has_user(us, u2));
}

}