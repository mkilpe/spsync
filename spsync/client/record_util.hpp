#pragma once

#include "record_data.hpp"

#include <spsync/core/crypto_context.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/record_interface.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/util/metadata.hpp>

#include <optional>

namespace securepath::sync {

std::optional<util::metadata> extract_single_object_meta(encryption_key_storage const& keys, record_handle h);
plain_user_change_data encrypt_last_key_for_users(users const& us, crypto_context& cc);

enum class record_order {
	seq_accending,
	seq_descending
};

/// Helper class to get/search decrypted data records
struct search_data_records {
	search_data_records(crypto_context& cc);

	/// Set the ordering of returned records
	void ordering(record_order);

	/// Set if only in sync records are returned (in opposed to also containing records which are pending commits)
	void only_in_sync(bool);

	/// Main function to get the result, return at most max entries. Can be called multiple times if not all matched records are returned at once
	std::deque<single_data_change> get(std::size_t max = 0);

private:
	single_data_change decrypt_data_record(record_handle) const;

private:
	crypto_context& cc_;
	record_order ordering_{record_order::seq_descending};
	bool only_in_sync_{true};
	std::optional<sequence_number> cur_seq_;
};

}
