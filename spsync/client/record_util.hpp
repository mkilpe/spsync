#pragma once

#include <spsync/core/crypto_context.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/record_interface.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/util/metadata.hpp>

#include <optional>

namespace securepath::sync {

std::optional<util::metadata> extract_single_object_meta(encryption_key_storage const& keys, record_handle h);

plain_user_change_data encrypt_last_key_for_users(users const& us, crypto_context& cc);

}
