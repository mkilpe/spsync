#include <spsync/engine/rebase_policy.hpp>

#include <securepath/test_frame/test_suite.hpp>

namespace securepath::sync {
namespace {

octet_vector h(char c) { return octet_vector(4, std::uint8_t(c)); }

rebase_state base_state(sync_mode mode, record_type_tag type) {
	rebase_state s;
	s.mode = mode;
	s.type = type;
	s.last_seen = chain_block_id{sequence_number{3}, h('a')};
	s.head = chain_block_id{sequence_number{3}, h('a')};
	return s;
}

}

TEST_CASE("rebase policy require_all_seen", "[unit]") {
	for(auto type : {data_change_record_tag, user_change_record_tag, segment_record_tag}) {
		auto s = base_state(sync_mode::require_all_seen, type);
		CHECK(!needs_rebase(s));
		s.head = chain_block_id{sequence_number{4}, h('b')};
		CHECK(needs_rebase(s));
	}
}

TEST_CASE("rebase policy allow_all", "[unit]") {
	for(auto type : {data_change_record_tag, user_change_record_tag, segment_record_tag}) {
		auto s = base_state(sync_mode::allow_all, type);
		s.has_adds = true;
		s.head = chain_block_id{sequence_number{10}, h('b')};
		s.last_special = sequence_number{9};
		s.last_data_add = sequence_number{10};
		CHECK(!needs_rebase(s));
	}
}

TEST_CASE("rebase policy require_special_seen", "[unit]") {
	// user change behind a newer special record
	auto s = base_state(sync_mode::require_special_seen, user_change_record_tag);
	s.head = chain_block_id{sequence_number{5}, h('b')};
	s.last_special = sequence_number{4};
	CHECK(needs_rebase(s));
	s.last_special = sequence_number{3}; // has seen the newest special
	CHECK(!needs_rebase(s));

	// data change behind a newer special record
	s = base_state(sync_mode::require_special_seen, data_change_record_tag);
	s.has_adds = true;
	s.head = chain_block_id{sequence_number{5}, h('b')};
	s.last_special = sequence_number{4};
	CHECK(needs_rebase(s));
	s.last_special = sequence_number{3};
	// newer adds do not matter in this mode
	s.last_data_add = sequence_number{5};
	CHECK(!needs_rebase(s));

	// segments have to be at the head
	s = base_state(sync_mode::require_special_seen, segment_record_tag);
	CHECK(!needs_rebase(s));
	s.head = chain_block_id{sequence_number{4}, h('b')};
	CHECK(needs_rebase(s));
}

TEST_CASE("rebase policy require_data_add_remove_seen", "[unit]") {
	// adding data change behind a newer add
	auto s = base_state(sync_mode::require_data_add_remove_seen, data_change_record_tag);
	s.has_adds = true;
	s.head = chain_block_id{sequence_number{5}, h('b')};
	s.last_data_add = sequence_number{4};
	CHECK(needs_rebase(s));
	s.last_data_add = sequence_number{3};
	CHECK(!needs_rebase(s));

	// a data change without adds ignores the add cursor
	s.has_adds = false;
	s.last_data_add = sequence_number{5};
	CHECK(!needs_rebase(s));

	// but a newer special record forces a rebase for any data change
	s.last_special = sequence_number{4};
	CHECK(needs_rebase(s));
}

}
