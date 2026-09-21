#include "data_release.hpp"

namespace securepath::sync {

std::vector<protocol::release_data> release_packets(protocol::storage_id const& sid
	, std::vector<data_id> const& ids, std::size_t batch)
{
	std::vector<protocol::release_data> ret;
	for(auto& run : in_batches(ids, batch)) {
		ret.emplace_back(sid, std::move(run));
	}
	return ret;
}

std::vector<protocol::replicate_data> replicate_packets(protocol::storage_id const& sid
	, std::vector<data_descriptor> const& descriptors, std::size_t batch)
{
	std::vector<protocol::replicate_data> ret;
	for(auto& run : in_batches(descriptors, batch)) {
		ret.emplace_back(sid, std::move(run));
	}
	return ret;
}

}
