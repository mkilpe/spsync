#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/protocol/error.hpp>
#include <spsync/server/server_lib/storage.hpp>

#include <filesystem>

namespace securepath::sync {

TEST_CASE("storage modes are persisted and immutable", "[unit]") {
	std::string const root = "test-storage-root";
	std::filesystem::remove_all(root);
	protocol::storage_id sid = securepath::test::random_octet_vector(8);
	storage_config cfg{root};

	{
		storage s(sid, cfg, storage_modes{sync_mode::require_special_seen, auth_mode::only_tag});
		CHECK(s.modes().mode == sync_mode::require_special_seen);
		CHECK(s.modes().auth == auth_mode::only_tag);
	}
	{
		// reopen without a request: the persisted modes are used
		storage s(sid, cfg);
		CHECK(s.modes().mode == sync_mode::require_special_seen);
	}
	{
		// reopen with the same requested modes is fine
		storage s(sid, cfg, storage_modes{sync_mode::require_special_seen, auth_mode::only_tag});
		CHECK(s.modes().mode == sync_mode::require_special_seen);
	}
	// requesting different modes for an existing storage must fail
	CHECK_THROWS(storage(sid, cfg, storage_modes{sync_mode::require_all_seen, auth_mode::only_tag}));
	CHECK_THROWS(storage(sid, cfg, storage_modes{sync_mode::require_special_seen, auth_mode::sign_records}));

	std::filesystem::remove_all(root);
}

}
