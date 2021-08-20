#pragma once

#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/record_interface.hpp>
#include <spsync/util/metadata.hpp>

#include <optional>

namespace securepath::sync {

std::optional<util::metadata> extract_single_object_meta(encryption_key_storage const& keys, record_handle h);

}
