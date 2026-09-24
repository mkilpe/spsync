#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/transfer/piece_cursor.hpp>

namespace securepath::sync {

// the pieces of a transfer, as both the uploader and the downloader hand them out
TEST_CASE("piece cursor", "[unit]") {
	// 2500 octets in chunks of 1000 plus a 16 octet tag each: 1016, 1016 and 468
	data_descriptor const d{2500, 1000, securepath::test::random_octet_vector(64)};
	REQUIRE(d.chunk_count() == 3);
	piece_cursor cursor{d};
	CHECK(cursor.descriptor() == d);
	CHECK(cursor.done());
	CHECK(!cursor.starting_chunk());
	CHECK(!cursor.next(600));

	// the chunks in the order they were added, each in pieces from offset 0, the last
	// piece of a chunk and the last chunk as short as they are
	cursor.add(0);
	cursor.add(2);
	CHECK(!cursor.done());
	CHECK(cursor.starting_chunk() == 0);
	CHECK(cursor.next(600) == piece_range{0, 0, 600});
	CHECK(!cursor.starting_chunk());
	CHECK(!cursor.done());
	CHECK(cursor.next(600) == piece_range{0, 600, 416});
	CHECK(cursor.starting_chunk() == 2);
	CHECK(cursor.next(600) == piece_range{2, 0, 468});
	CHECK(cursor.done());
	CHECK(!cursor.starting_chunk());
	CHECK(!cursor.next(600));

	// a chunk can be added while another is on its way
	cursor.add(1);
	CHECK(cursor.starting_chunk() == 1);
	CHECK(cursor.next(1016) == piece_range{1, 0, 1016});
	CHECK(cursor.done());

	// pieces of nothing move one octet; a piece bigger than the chunk moves it whole
	piece_cursor tiny{d};
	tiny.add(2);
	CHECK(tiny.next(0) == piece_range{2, 0, 1});
	CHECK(tiny.next(0) == piece_range{2, 1, 1});
	piece_cursor whole{d};
	whole.add(2);
	CHECK(whole.next(5000) == piece_range{2, 0, 468});
	CHECK(whole.done());

	// a default cursor has nothing to say
	piece_cursor none;
	CHECK(none.done());
	none.add(0);
	CHECK(none.next(10) == piece_range{0, 0, 0});
	CHECK(none.done());
}

}
