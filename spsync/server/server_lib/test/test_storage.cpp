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


TEST_CASE("replicated storage requires signed records", "[unit]") {
	std::string const root = "test-storage-root-repl";
	std::filesystem::remove_all(root);
	protocol::storage_id sid = securepath::test::random_octet_vector(8);
	storage_config cfg{root};

	// replication without signing is refused
	CHECK_THROWS(storage(sid, cfg, storage_modes{sync_mode::require_all_seen, auth_mode::only_tag, replication_mode::weak}));

	// with signing it is fine and the replication mode is persisted
	{
		storage s(sid, cfg, storage_modes{sync_mode::require_all_seen, auth_mode::sign_records, replication_mode::weak});
		CHECK(s.modes().replication == replication_mode::weak);
	}
	{
		storage s(sid, cfg);
		CHECK(s.modes().replication == replication_mode::weak);
		CHECK(s.modes().auth == auth_mode::sign_records);
	}
	// a different replication mode for an existing storage is a mismatch
	CHECK_THROWS(storage(sid, cfg, storage_modes{sync_mode::require_all_seen, auth_mode::sign_records, replication_mode::strict}));

	std::filesystem::remove_all(root);
}

}
