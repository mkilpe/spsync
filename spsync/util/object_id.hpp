#pragma once

#include <securepath/util/octet_vector.hpp>
#include <spsync/util/format.hpp>
#include <securepath/serialisation/sequence.hpp>

#include <iosfwd>
#include <string>
#include <map>

namespace securepath::sync::util {

/**
 * \brief Unique identifier for object
 *
 * This is per storage unique id for object
**/
class object_id {
public:
	/// construct object id from vector of octets
	explicit object_id(octet_vector = {});

	/// returns true if this object id is valid
	bool is_valid() const;

	/// returns the contained value
	octet_vector const& value() const;

	/// to hexadecimal presentation
	std::string to_hex() const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & id_;
	}
private:
	octet_vector id_;
};

/// returns random object id
object_id create_object_id();

bool operator==(object_id const& left, object_id const& right);
bool operator!=(object_id const& left, object_id const& right);
bool operator<(object_id const& left, object_id const& right);

std::ostream& operator<<(std::ostream&, object_id const&);

}


SPSYNC_FORMAT_VIA_OSTREAM(securepath::sync::util::object_id)

