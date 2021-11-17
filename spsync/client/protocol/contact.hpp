#pragma once

#include <spsync/client/types.hpp>


namespace securepath::sync::client::protocol {
inline namespace v1 {

struct contact_data {
	/// Name of the sender
	std::string name;
	/// Message for convenience
	std::string message;
	serialisation::trailing_data trailing;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & name & message & trailing;
	}
};

struct invitation_data {
	/// Storage you are invited to
	storage_id sid;
	/// Servers of the storage
	host_port key_server;
	host_port sync_server;

	/// First block this invited user will have access to for authentication purposes
	chain_block_id chain_id;

	/// Possible encryption keys for the storage if sent over
	std::vector<encryption_key> enc_keys;

	/// Human readable name of the storage
	std::string name;
	/// Message for convenience
	std::string message;
	serialisation::trailing_data trailing;

	storage_info to_storage_info() const {
		return storage_info{sid, key_server, sync_server, chain_id, enc_keys};
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & sid & key_server & sync_server & chain_id & enc_keys & name & message & trailing;
	}
};

}
}