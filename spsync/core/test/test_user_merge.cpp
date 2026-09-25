// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/core/user_merge.hpp>

#include <algorithm>

namespace securepath::sync {
namespace {

record_tag tag_of(std::uint8_t filler) {
	return record_tag(16, filler);
}

util::user_id uid(std::uint8_t filler) {
	return util::user_id{crypto::public_key_id{octet_vector(32, filler)}};
}

users delta_add(util::user_id u, util::access_type a = util::access_type::data_access) {
	users us{users_change_mode::delta};
	us.add(util::user_access{std::move(u), a});
	return us;
}

users delta_remove(util::user_id u) {
	users us{users_change_mode::delta};
	us.remove(std::move(u));
	return us;
}

bool has_member(std::vector<util::user_access> const& members, util::user_id const& u) {
	return std::ranges::find_if(members, [&](auto const& ua) { return ua.user == u; }) != members.end();
}

}

// the D9 merge fold (plan 4.6): deterministic on the record set, removal beats a
// concurrent addition, an addition that saw the removal wins
TEST_CASE("user merge fold", "[unit]") {
	auto const x = uid(0x11);
	// the special tree: root R(1); linear chain R -> A(2) -> B(3); C(4) is R's sibling
	// branch (concurrent with A and B)
	std::map<record_tag, record_tag> parents{
		{tag_of(1), {}},
		{tag_of(2), tag_of(1)},
		{tag_of(3), tag_of(2)},
		{tag_of(4), tag_of(1)},
	};

	SECTION("linear history: add then remove -> gone; remove then a re-add that saw it -> member") {
		std::vector<user_change_entry> entries{
			{delta_add(x), tag_of(2), tag_of(1)},
			{delta_remove(x), tag_of(3), tag_of(2)},
		};
		CHECK(!has_member(merge_user_changes(entries, parents), x));

		entries.push_back({delta_add(x), tag_of(4), tag_of(3)});
		auto with_readd = parents;
		with_readd[tag_of(4)] = tag_of(3);
		CHECK(has_member(merge_user_changes(entries, with_readd), x));
	}
	SECTION("concurrent branches: add on one, remove on the other -> removed, in EITHER local order") {
		std::vector<user_change_entry> add_first{
			{delta_add(x), tag_of(2), tag_of(1)},     // branch 1
			{delta_remove(x), tag_of(4), tag_of(1)},  // concurrent branch 2
		};
		std::vector<user_change_entry> remove_first{add_first[1], add_first[0]};
		CHECK(!has_member(merge_user_changes(add_first, parents), x));
		CHECK(!has_member(merge_user_changes(remove_first, parents), x));
	}
	SECTION("concurrent adds: the smallest tag wins deterministically, access is not unioned") {
		std::vector<user_change_entry> one{
			{delta_add(x, util::access_type::data_read_access), tag_of(2), tag_of(1)},
			{delta_add(x, util::access_type::all_access), tag_of(4), tag_of(1)},
		};
		std::vector<user_change_entry> two{one[1], one[0]};
		auto m1 = merge_user_changes(one, parents);
		auto m2 = merge_user_changes(two, parents);
		REQUIRE(m1.size() == 1);
		REQUIRE(m2.size() == 1);
		CHECK(m1[0].access == util::access_type::data_read_access);
		CHECK(m2[0].access == util::access_type::data_read_access);
	}
	SECTION("a causally newer update supersedes an older one regardless of local order") {
		std::vector<user_change_entry> entries{
			{delta_add(x, util::access_type::all_access), tag_of(3), tag_of(2)},
			{delta_add(x, util::access_type::data_read_access), tag_of(2), tag_of(1)},
		};
		auto m = merge_user_changes(entries, parents);
		REQUIRE(m.size() == 1);
		CHECK(m[0].access == util::access_type::all_access);
	}
	SECTION("legacy full mode resets the fold") {
		auto const y = uid(0x22);
		users full{users_change_mode::full};
		full.add(util::user_access{y, util::access_type::data_access});
		std::vector<user_change_entry> entries{
			{delta_add(x), tag_of(2), tag_of(1)},
			{full, tag_of(3), tag_of(2)},
		};
		auto m = merge_user_changes(entries, parents);
		CHECK(!has_member(m, x));
		CHECK(has_member(m, y));
	}
}

}
