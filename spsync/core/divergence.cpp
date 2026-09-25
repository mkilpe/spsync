#include "divergence.hpp"

#include <algorithm>

namespace securepath::sync {

std::vector<sequence_number> sample_sequences(sequence_number head) {
	std::vector<sequence_number> ret;
	if(head.is_valid()) {
		ret.push_back(head);
		// the distance doubles; the shift is bounded so a head near 2^64 cannot wrap it
		for(unsigned shift = 0; shift < 63 && (std::uint64_t{1} << shift) < head.value; ++shift) {
			ret.push_back(sequence_number{head.value - (std::uint64_t{1} << shift)});
		}
		if(ret.back() != sequence_number{1}) {
			ret.push_back(sequence_number{1});
		}
	}
	return ret;
}

divergence find_divergence(std::vector<chain_block_id> const& samples, held_hash const& held) {
	divergence ret;
	for(auto const& sample : samples) {
		auto const hash = sample.sequence.is_valid() ? held(sample.sequence) : octet_vector{};
		// a sample not held says nothing
		if(!hash.empty()) {
			if(hash == sample.hash) {
				ret.last_common = std::max(ret.last_common, sample.sequence);
			} else if(!ret.first_divergent.is_valid() || sample.sequence < ret.first_divergent) {
				ret.first_divergent = sample.sequence;
			}
		}
	}
	return ret;
}

pull_range plan_pull(sequence_number known, sequence_number peer_head, divergence const& div) {
	pull_range ret;
	auto const held = std::max(known, div.last_common);
	if(!div.diverged() && peer_head.is_valid() && held < peer_head) {
		ret = pull_range{held + 1, peer_head};
	}
	return ret;
}

}
