// SPDX-License-Identifier: MIT

#pragma once

#include "record_data.hpp"

#include <spsync/core/crypto_context.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/record_interface.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/util/metadata.hpp>

#include <optional>

namespace securepath::sync {

plain_user_change_data encrypt_last_key_for_users(users const& us, crypto_context& cc);
error extract_single_data_changes(encryption_key_storage const&, record_handle, std::deque<single_data_change>&);

}
