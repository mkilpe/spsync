// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/data/data_descriptor.hpp>
#include <spsync/protocol/s2s_protocol.hpp>

#include <algorithm>
#include <vector>

namespace securepath::sync {

/// ids per release_data packet, descriptors per replicate_data packet: like the
/// announcements of a data server
std::size_t constexpr release_batch_size{500};

/// the items in runs of at most `batch` (at least one), in order; none for no items
template<typename T>
[[nodiscard]] std::vector<std::vector<T>> in_batches(std::vector<T> const& items, std::size_t batch = release_batch_size) {
	std::vector<std::vector<T>> ret;
	auto const size = std::max<std::size_t>(batch, 1);
	for(std::size_t first = 0; first < items.size(); first += size) {
		auto const count = std::min(size, items.size() - first);
		auto const begin = items.begin() + static_cast<std::ptrdiff_t>(first);
		ret.emplace_back(begin, begin + static_cast<std::ptrdiff_t>(count));
	}
	return ret;
}

/**
 * The release of the given record data of a storage (record_data.txt RD9) as s2s
 * packets of at most `batch` ids each, in the given order; none for no ids. A cut of a
 * big storage may release more ids than one frame carries.
 */
[[nodiscard]] std::vector<protocol::release_data> release_packets(protocol::storage_id const& sid
	, std::vector<data_id> const& ids, std::size_t batch = release_batch_size);

/// the same for the copies a data server is to hold (RD13 replication)
[[nodiscard]] std::vector<protocol::replicate_data> replicate_packets(protocol::storage_id const& sid
	, std::vector<data_descriptor> const& descriptors, std::size_t batch = release_batch_size);

}
