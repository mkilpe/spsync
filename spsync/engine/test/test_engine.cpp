#include <spsync/test/engine_context.hpp>

#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

namespace securepath::sync::util {

struct check_user_change_visitor {
	users expected_users;

	void operator()(user_change_record const& r) const {
		CHECK(r.data().access() == expected_users);
	}

	template<typename Record>
	void operator()(Record const&) const {
		CHECK(false);
	}
};

void check_user_change(serialised_record const& r, users const& expected_users) {
	r.deserialise_record(check_user_change_visitor{expected_users});
}


TEST_CASE("engine initual record", "[unit]") {
	test::engine_context context;

	context.io.add_commit_record_response([&](record_handle h)
		{
			users initial;
			initial.add(util::user_access{context.root_user, util::access_type::user_management_access});

			check_user_change(h->record(), initial);
			return h->record();
		});
	context.create_initial_record();
	CHECK(context.io.process_event());
}

}
