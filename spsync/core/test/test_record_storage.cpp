#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/core/record_storage.hpp>
#include <spsync/core/records/user_change_record.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/octet_vector.hpp>

namespace securepath::sync::util {

std::string const db_name = "record_storage_test.db";

static void remove_database_test_db() {
	std::remove(db_name.c_str());
}

struct test_record_creator {

	auth_record<user_change_record> test_user_change() {
		record_tag tag = test::random_octet_vector(16);
		auth_record<user_change_record> test_record{
			user_change_record{record_base{
				last_server_seq++, previous_tag, octet_vector{}, sequence_number{1}},
				plain_user_change_data{},
				encrypted_record_header<user_change_header>{}}, content_auth{tag}};
		previous_tag = tag;
		return test_record;
	}

	sequence_number last_server_seq{};
	record_tag previous_tag{};
};

TEST_CASE("record_storage", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);

	CHECK(storage.last_sequence_number() == sequence_number{});
	CHECK_THROWS(storage.find_last());
	CHECK_THROWS(storage.find_last(object_id{}));
	CHECK_THROWS(storage.find_first(object_id{}));
	CHECK_THROWS(storage.find(record_tag{}));

	test_record_creator creator;
	CHECK(storage.create(creator.test_user_change()));

	{ // check find_last returns correct data
		auto h = storage.find_last();
		CHECK(h->tag() == creator.previous_tag);
		CHECK(h->previous_tag().empty());
		CHECK(h->seq() == sequence_number{});
		CHECK(h->state() == record_state::unknown);
	}
	{ // check find returns correcr data
		auto h = storage.find(creator.previous_tag);
		CHECK(h->tag() == creator.previous_tag);
		CHECK(h->previous_tag().empty());
		CHECK(h->seq() == sequence_number{});
		CHECK(h->state() == record_state::unknown);
	}
	{ //set state and server sequence
		auto h = storage.find_last();
		h->set_state(record_state::in_sync, creator.last_server_seq);
		CHECK(storage.last_sequence_number() == creator.last_server_seq);
		CHECK(h->seq() == creator.last_server_seq);
		CHECK(h->state() == record_state::in_sync);
	}

	{ // check that creating new record has correct data
		record_tag previous_tag = creator.previous_tag;
		CHECK(storage.create(creator.test_user_change()));
		auto h = storage.find(creator.previous_tag);
		CHECK(h->tag() == creator.previous_tag);
		CHECK(h->previous_tag() == previous_tag);
		CHECK(h->seq() == sequence_number{});
		CHECK(h->state() == record_state::unknown);

		h->set_state(record_state::in_sync, creator.last_server_seq);
		h = storage.find_last();
		CHECK(h->tag() == creator.previous_tag);
		CHECK(storage.last_sequence_number() == creator.last_server_seq);
	}

}

}
