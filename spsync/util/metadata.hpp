// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/octet_vector.hpp>
#include <securepath/serialisation/map.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/util.hpp>

#include <string>
#include <map>

namespace securepath::sync::util {

/**
 * \brief Key value pair for metadata.
 *
 * Keeps arbitrary metadata as serialised, the wanted data with a type can be queried.
**/
class metadata {
public:
	using key_type = std::string;

	metadata() = default;
	metadata(std::initializer_list<std::pair<key_type const, octet_vector>>);

	/// insert (or replace) typed data which will be serialised
	template<typename Data>
	void insert(key_type const& key, Data const& data) {
		insert(key, serialisation::asn_der_serialise(data));
	}

	/// insert (or replace) octet vector raw data
	void insert(key_type const& key, octet_vector);

	/// find data matching the key and return typed object
	/// \throws serialisation_error if type of the serialised object doesn't match
	template<typename Data>
	std::optional<Data> find(key_type const& key) const {
		std::optional<Data> ret;
		auto v = find(key);
		if(v) {
			ret = serialisation::asn_der_deserialise<Data>(*v);
		}
		return ret;
	}

	/// find data matching the key
	std::optional<octet_vector> find(key_type const& key) const;

	/// remove data associated with the key
	void erase(key_type const& key);

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & data_ & trailing_data_;
	}

	/// Returns true if there is no meta-data
	bool empty() const;

	bool operator==(metadata const& m) const;
private:
	std::map<key_type, octet_vector> data_;
	serialisation::trailing_data trailing_data_;
};

}

