#pragma once

#include "metadata.hpp"
#include <spsync/util/format.hpp>

#include <securepath/crypto/public_key_id.hpp>
#include <securepath/serialisation/decls.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/util/host_port.hpp>
#include <securepath/util/types.hpp>

#include <iosfwd>

namespace securepath::sync::util {

/**
 * \brief Unique id for user
 *
 * This is unique id for user which is used for the access control in chain storage
**/
class user_id {
public:
	/// Construct user_id from public key id
	user_id(crypto::public_key_id = {});

	/// Returns true if this user id is valid
	bool is_valid() const;

	/// Get underlying public key id
	crypto::public_key_id public_key_id() const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & id_ & trailing_data_;
	}
private:
	crypto::public_key_id id_;
	serialisation::trailing_data trailing_data_;
};


bool operator==(user_id const& left, user_id const& right);
bool operator<(user_id const& left, user_id const& right);

std::ostream& operator<<(std::ostream&, user_id const&);

class user : public metadata {
public:
	user() = default;
	user(user_id id, host_port hp);

	/// Returns true if this user is valid
	bool is_valid() const;

	user_id id() const;
	host_port key_server() const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & id_ & key_server_ & static_cast<metadata&>(*this) & trailing_data_;
	}

private:
	user_id id_;
	/// what server the key belongs to
	host_port key_server_;
	serialisation::trailing_data trailing_data_;
};

std::ostream& operator<<(std::ostream&, user const&);

/// User access type to storage
enum class access_type {
	no_access = 0x0,
	data_read_access = 0x1,
	data_write_access = 0x2,
	user_management_access = 0x4,

	data_access = data_read_access | data_write_access,
	all_access = data_access | user_management_access
};

serialisation::serialiser& serialise(serialisation::serialiser& s, access_type const& v);
serialisation::deserialiser& serialise(serialisation::deserialiser& s, access_type& v);

std::ostream& operator<<(std::ostream&, access_type const&);


/**
 * \brief Access for specific user to a storage
 *
**/
struct user_access {
	user_id user;
	access_type access{};

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & user & access;
	}
};

bool operator==(user_access const& l, user_access const& r);

std::ostream& operator<<(std::ostream&, user_access const&);

}


SPSYNC_FORMAT_VIA_OSTREAM(securepath::sync::util::user_id)
SPSYNC_FORMAT_VIA_OSTREAM(securepath::sync::util::user)
SPSYNC_FORMAT_VIA_OSTREAM(securepath::sync::util::access_type)
SPSYNC_FORMAT_VIA_OSTREAM(securepath::sync::util::user_access)

