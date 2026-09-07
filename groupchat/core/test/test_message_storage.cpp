#include <groupchat/core/message_storage.hpp>

#include <spsync/test/test_block_creator.hpp>

#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/engine/record_creator.hpp>
#include <spsync/engine/record_verifier.hpp>
#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>


namespace securepath::groupchat::test {

static message_id new_message_id() {
	return message_id{securepath::test::random_octet_vector(8)};
}

TEST_CASE("message_storage test", "[unit]") {
	std::remove("message_storage.db");
	message_storage s(database::sqlite::create_sqlite_connection("message_storage.db"));

	sync::sequence_number impl_seq{0};
	auto make_msg = [&impl_seq](std::string s) mutable
		{
			msg_data d;
			d.message = s;
			d.seq = ++impl_seq;
			return d;
		};

	CHECK(s.get(message_search{}).empty());
	CHECK(s.latest_sequence() == sync::sequence_number{});

	msg_change c = s.insert(new_message_id(), make_msg("1"), msg_state::in_sync);
	CHECK(c.new_index == 1);
	CHECK(c.old_index == 0);
	CHECK(c.state == msg_state::in_sync);
	CHECK(s.latest_sequence() == sync::sequence_number{1});
	{
		auto list = s.get(message_search{});
		REQUIRE(list.size() == 1);
		CHECK(list[0].data == "1");
		CHECK(list[0].index == 1);
	}
	{
		auto list = s.get(message_search{0,0,msg_order::index_ascending});
		REQUIRE(list.size() == 1);
		CHECK(list[0].data == "1");
		CHECK(list[0].index == 1);
	}
	auto pid = new_message_id();
	c = s.insert(pid, make_msg("2"), msg_state::pending);
	CHECK(c.new_index == 2);
	CHECK(c.old_index == 0);
	CHECK(c.id == pid);
	CHECK(c.state == msg_state::pending);
	CHECK(s.latest_sequence() == sync::sequence_number{1});
	{
		auto list = s.get(message_search{});
		REQUIRE(list.size() == 2);
		CHECK(list[0].data == "2");
		CHECK(list[0].index == 2);
		CHECK(list[0].state == msg_state::pending);
		CHECK(list[1].data == "1");
		CHECK(list[1].index == 1);
		CHECK(list[1].state == msg_state::in_sync);
	}
	{
		auto list = s.get(message_search{0,0,msg_order::index_ascending});
		REQUIRE(list.size() == 2);
		CHECK(list[0].data == "1");
		CHECK(list[0].index == 1);
		CHECK(list[0].state == msg_state::in_sync);
		CHECK(list[1].data == "2");
		CHECK(list[1].index == 2);
		CHECK(list[1].state == msg_state::pending);
	}
	{
		auto list = s.get(message_search{0, 1});
		REQUIRE(list.size() == 1);
		CHECK(list[0].data == "2");
		CHECK(list[0].index == 2);
	}
	{
		auto list = s.get(message_search{0,1,msg_order::index_ascending});
		REQUIRE(list.size() == 1);
		CHECK(list[0].data == "1");
		CHECK(list[0].index == 1);
	}
	c = s.insert(pid, make_msg("2"), msg_state::in_sync);
	CHECK(c.new_index == 2);
	CHECK(c.old_index == 2);
	CHECK(c.id == pid);
	CHECK(c.state == msg_state::in_sync);
	{
		auto list = s.get(message_search{});
		REQUIRE(list.size() == 2);
		CHECK(list[0].data == "2");
		CHECK(list[0].index == 2);
		CHECK(list[0].state == msg_state::in_sync);
		CHECK(list[1].data == "1");
		CHECK(list[1].index == 1);
		CHECK(list[1].state == msg_state::in_sync);
	}
	for(int i = 3; i != 100; ++i) {
		s.insert(new_message_id(), make_msg(std::to_string(i)), msg_state::in_sync);
	}
	for(int i = 100; i != 107; ++i) {
		s.insert(new_message_id(), make_msg(std::to_string(i)), msg_state::pending);
	}
	CHECK(s.latest_sequence() == sync::sequence_number{100});
	{
		auto list = s.get(message_search{});
		REQUIRE(list.size() == 106);
		CHECK(list[0].data == "106");
		CHECK(list[0].index == 106);
	}
	SECTION("chunk") {
		int chuck_size = GENERATE(1,2,3,7,12,23,30);
		int total_amount = 106;
		while(total_amount > 0) {
			auto list = s.get(message_search{total_amount, std::size_t(chuck_size)});
			REQUIRE(list.size() <= total_amount);
			REQUIRE((list.size() == total_amount || list.size() == chuck_size));
			for(int i = 0; i != list.size(); ++i) {
				auto v = total_amount-i;
				REQUIRE(list[i].data == std::to_string(v));
				REQUIRE(list[i].index == v);
			}
			total_amount -= list.size();
		}
	}

	// mark one of the pending ones as synced and try again
	auto list = s.get(message_search{0, 5});
	c = s.insert(list[4].mid, make_msg(list[4].data), msg_state::in_sync);
	CHECK(c.new_index == 100);
	CHECK(c.old_index == list[4].index);
	CHECK(c.id == list[4].mid);
	CHECK(c.state == msg_state::in_sync);
	SECTION("chunk2") {
		int chuck_size = GENERATE(1,2,3,12,30);
		int total_amount = 106;
		while(total_amount > 0) {
			auto list = s.get(message_search{total_amount, std::size_t(chuck_size)});
			REQUIRE(list.size() <= total_amount);
			REQUIRE((list.size() == total_amount || list.size() == chuck_size));
			for(int i = 0; i != list.size(); ++i) {
				auto v = total_amount-i;
				REQUIRE(list[i].index == v);
			}
			total_amount -= list.size();
		}
	}
}


struct test_message_creator {

	test_message_creator()
	: key(sync::sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size()))
	{}

	/// Create empty user change record for testing
	sync::chain_block test_user_change() {
		sync::user_change_record_creator creator(key, sync::chain_block_id{last_server_seq, prevhash});
		//set the user change for this record
		creator.set_change(sync::plain_user_change_data{}, sync::metadata{});
		sync::chain_block block{creator.result(), ++last_server_seq};
		prevhash = block.hash();
		return block;
	}

	sync::chain_block test_message(std::string m) {
		sync::data_change_record_creator creator(key, sync::chain_block_id{last_server_seq, prevhash});

		sync::metadata header;
		header.insert(groupchat_message_id, message_data{m});

		creator.add_change(sync::util::create_object_id(), sync::record_tag{}, header);
		sync::chain_block block{creator.result(), ++last_server_seq};
		prevhash = block.hash();
		return block;
	}

	sync::encryption_key key;
	sync::sequence_number last_server_seq;
	octet_vector prevhash;
};

TEST_CASE("message_storage sync test", "[unit]") {
	std::remove("message_storage.db");
	auto db = database::sqlite::create_sqlite_connection("message_storage.db");

	sync::encryption_key_storage keys(db);
	sync::record_storage rs(db);
	message_storage ms(db);

	test_message_creator creator;
	keys.insert(creator.key);

	sync_message_storage(ms, rs, keys);

	REQUIRE(ms.latest_sequence() == sync::sequence_number{});

	// first record needs to be user_change
	rs.create(creator.test_user_change(), sync::record_state::in_sync);

	for(int i = 0; i != 5; ++i) {
		rs.create(creator.test_message(std::to_string(i)), sync::record_state::in_sync);
	}
	sync_message_storage(ms, rs, keys);

	REQUIRE(rs.last_block().sequence == creator.last_server_seq);
	REQUIRE(ms.latest_sequence() == creator.last_server_seq);
	REQUIRE(ms.get(message_search{}).size() == 5);

	for(int i = 0; i != 5; ++i) {
		rs.create(creator.test_message(std::to_string(i)), sync::record_state::pending_commit);
	}
	sync_message_storage(ms, rs, keys);

	REQUIRE(ms.get(message_search{}).size() == 10);

	// a restart while the records are still pending reconciles them again (the cli
	// crashed on the unique message id here)
	sync_message_storage(ms, rs, keys);
	REQUIRE(ms.get(message_search{}).size() == 10);
	{
		message_storage reopened(db);
		sync_message_storage(reopened, rs, keys);
		REQUIRE(reopened.get(message_search{}).size() == 10);
	}

	for(auto h = rs.find_first_pending_commit(); h; h = rs.find_first_pending_commit()) {
		h->set_state(sync::record_state::in_sync);
	}
	sync_message_storage(ms, rs, keys);

	REQUIRE(rs.last_block().sequence == creator.last_server_seq);
	REQUIRE(ms.latest_sequence() == creator.last_server_seq);
	REQUIRE(ms.get(message_search{}).size() == 10);

	rs.create(creator.test_message("a"), sync::record_state::pending_commit);
	REQUIRE(rs.last_block().sequence == creator.last_server_seq-1);

	// the pending commit should not be counted as sequence, so remove one
	creator.last_server_seq -= 1;

	rs.create(creator.test_message("b"), sync::record_state::in_sync);
	REQUIRE(rs.last_block().sequence == creator.last_server_seq);

	sync_message_storage(ms, rs, keys);

	REQUIRE(rs.last_block().sequence == creator.last_server_seq);
	REQUIRE(ms.latest_sequence() == creator.last_server_seq);
	REQUIRE(ms.get(message_search{}).size() == 12);

	auto h = rs.find_first_pending_commit();
	REQUIRE(h);
	h->set_state(sync::record_state::in_sync, sync::chain_block_id{creator.last_server_seq+1, h->record().hash()});

	sync_message_storage(ms, rs, keys);
	REQUIRE(rs.last_block().sequence == creator.last_server_seq+1);
	REQUIRE(ms.latest_sequence() == creator.last_server_seq+1);
	REQUIRE(ms.get(message_search{}).size() == 12);
}


TEST_CASE("message_storage sender time order", "[unit]") {
	std::remove("message_storage_time.db");
	message_storage s(database::sqlite::create_sqlite_connection("message_storage_time.db"));

	sync::sequence_number impl_seq{0};
	auto make_msg = [&impl_seq](std::string text, int minutes) mutable
		{
			msg_data d;
			d.message = std::move(text);
			d.sender_time = serialisation::time_point{} + std::chrono::minutes(minutes);
			d.seq = ++impl_seq;
			return d;
		};

	// arrival (index) order differs from the sender time order, across both tables
	s.insert(new_message_id(), make_msg("t3", 3), msg_state::in_sync);
	s.insert(new_message_id(), make_msg("t1", 1), msg_state::in_sync);
	s.insert(new_message_id(), make_msg("t4", 4), msg_state::pending);
	s.insert(new_message_id(), make_msg("t2", 2), msg_state::pending);

	{
		auto list = s.get(message_search{.order=msg_order::time_ascending});
		REQUIRE(list.size() == 4);
		CHECK(list[0].data == "t1");
		CHECK(list[1].data == "t2");
		CHECK(list[2].data == "t3");
		CHECK(list[3].data == "t4");
	}
	{
		auto list = s.get(message_search{.order=msg_order::time_descending});
		REQUIRE(list.size() == 4);
		CHECK(list[0].data == "t4");
		CHECK(list[3].data == "t1");
	}
	{
		auto list = s.get(message_search{.max_count=2, .order=msg_order::time_descending});
		REQUIRE(list.size() == 2);
		CHECK(list[0].data == "t4");
		CHECK(list[1].data == "t3");
	}
	// index ordering is still available unchanged
	{
		auto list = s.get(message_search{.order=msg_order::index_ascending});
		REQUIRE(list.size() == 4);
		CHECK(list[0].data == "t3");
	}
}

}