#ifndef SPSYNC_UTIL_OBJECT_ID_HEADER
#define SPSYNC_UTIL_OBJECT_ID_HEADER

#include <securepath/util/octet_vector.hpp>
#include <securepath/serialisation/sequence.hpp>

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
	///Construct object id from vector of octets
	object_id(octet_vector = {});

	///Returns true if this object id is valid
	bool is_valid() const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & id_;
	}
private:
	octet_vector id_;
};

///Returns random object id
object_id create_object_id();

}

#endif