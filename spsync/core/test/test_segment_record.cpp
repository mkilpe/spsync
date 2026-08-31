#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/core/records/segment_record.hpp>

#include <spsync/test/test_block_creator.hpp>

namespace securepath::sync {

TEST_CASE("plain_segment_data round trip", "[unit]") {
	std::deque<record_tag> tags{securepath::test::random_octet_vector(16)
		, securepath::test::random_octet_vector(16)};
	record_tag prev = securepath::test::random_octet_vector(16);
	plain_segment_data data{sequence_number{2}, sequence_number{4}, tags, prev};

	CHECK(data.segment_start() == sequence_number{2});
	CHECK(data.segment_end() == sequence_number{4});
	CHECK(data.tags() == tags);
	CHECK(data.previous_segment_tag() == prev);

	auto back = serialisation::asn_der_deserialise<plain_segment_data>(
		serialisation::asn_der_serialise(data));
	CHECK(back.segment_start() == data.segment_start());
	CHECK(back.segment_end() == data.segment_end());
	CHECK(back.tags() == data.tags());
	CHECK(back.previous_segment_tag() == data.previous_segment_tag());

	// the first segment has no previous segment
	plain_segment_data first{sequence_number{1}, sequence_number{3}, tags};
	CHECK(first.previous_segment_tag().empty());
}

TEST_CASE("segment_header round trip", "[unit]") {
	util::metadata meta;
	meta.insert("purpose", std::string{"test"});
	segment_header header{meta};
	CHECK(header.metadata() == meta);
	CHECK(header.creation_time.time_since_epoch().count() != 0);

	auto back = serialisation::asn_der_deserialise<segment_header>(
		serialisation::asn_der_serialise(header));
	CHECK(back.metadata() == meta);
	CHECK(back.metadata().find<std::string>("purpose") == std::string{"test"});
}

TEST_CASE("segment record block round trip", "[unit]") {
	test::test_block_creator creator;
	auto b1 = creator.test_user_change();
	auto b2 = creator.test_data_change();

	plain_segment_data data{sequence_number{1}, sequence_number{3}
		, creator.created_tags};
	auto block = creator.test_segment(data);
	CHECK(block.sequence() == sequence_number{3});
	CHECK(creator.created_tags.size() == 3);

	auto rec = block.deserialise_to<segment_record>();
	CHECK(rec.data().segment_start() == sequence_number{1});
	CHECK(rec.data().segment_end() == sequence_number{3});
	REQUIRE(rec.data().tags().size() == 2);
	CHECK(rec.data().tags()[0] == b1.tag());
	CHECK(rec.data().tags()[1] == b2.tag());
	CHECK(rec.data().previous_segment_tag().empty());
	CHECK(!rec.op_id().empty());

	// the backbone: a later segment links the previous one by tag
	auto b3 = creator.test_data_change();
	plain_segment_data next{sequence_number{3}, sequence_number{5}
		, {block.tag(), b3.tag()}, block.tag()};
	auto next_seg = creator.test_segment(next);
	auto next_rec = next_seg.deserialise_to<segment_record>();
	CHECK(next_rec.data().previous_segment_tag() == block.tag());
	CHECK(next_rec.data().segment_start() == rec.data().segment_end());
}

}
