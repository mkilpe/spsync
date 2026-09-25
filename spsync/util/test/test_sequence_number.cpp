// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <spsync/util/sequence_number.hpp>

namespace securepath::sync::util {

TEST_CASE("sequence_number", "[unit]") {
	sequence_number seq;

	CHECK(test::check_serialisation(seq));
	CHECK(seq == sequence_number{0});
	CHECK(seq+1 == sequence_number{1});
	CHECK(1+seq == sequence_number{1});
	CHECK(seq+10 == sequence_number{10});
	CHECK(++seq == sequence_number{1});
	CHECK(seq++ == sequence_number{1});
	CHECK(seq != sequence_number{1});
	CHECK(seq == sequence_number{2});
	CHECK(sequence_number{0} < sequence_number{1});
	CHECK(sequence_number{2} < sequence_number{5});
	CHECK(!(sequence_number{1} < sequence_number{0}));

}

}
