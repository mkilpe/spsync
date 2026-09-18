#pragma once

#include "data_descriptor.hpp"

#include <securepath/serialisation/vector.hpp>

#include <vector>

namespace securepath::sync {

/**
 * The ordered chunk digests of a data (RD2). Sent ahead of an upload so the server can
 * check it against the committed descriptor and then every chunk against it.
 */
struct data_manifest {
	/// sha3-512 over the digests in order: the descriptor's manifest_digest / data_id
	octet_vector digest() const;

	/// true when this is the manifest the descriptor commits to (digest and chunk count)
	bool matches(data_descriptor const&) const;

	/// true when the encrypted chunk is the one the manifest names at that position
	bool verify_chunk(std::uint64_t chunk_no, octet_span encrypted) const;

	bool operator==(data_manifest const&) const = default;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & chunk_digests & trailing_data;
	}

public:
	std::vector<octet_vector> chunk_digests;
	serialisation::trailing_data trailing_data;
};

}
