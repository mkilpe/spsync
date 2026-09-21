#pragma once

#include <spsync/core/data/data_descriptor.hpp>
#include <spsync/protocol/s2s_protocol.hpp>

#include <vector>

namespace securepath::sync {

/// ids per release_data packet, like the announcements of a data server
std::size_t constexpr release_batch_size{500};

/**
 * The release of the given record data of a storage (record_data.txt RD9) as s2s
 * packets of at most `batch` ids each, in the given order; none for no ids. A cut of a
 * big storage may release more ids than one frame carries.
 */
[[nodiscard]] std::vector<protocol::release_data> release_packets(protocol::storage_id const& sid
	, std::vector<data_id> const& ids, std::size_t batch = release_batch_size);

}
