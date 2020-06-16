#ifndef SPSYNC_PROTOCOL_SERVER_PROTOCOL_HEADER
#define SPSYNC_PROTOCOL_SERVER_PROTOCOL_HEADER

#include "protocol_base.hpp"

namespace securepath::sync::protocol {
inline namespace v1 {

/// always first packet to negotiate version
struct server_hello : protocol_base {
	using protocol_base::protocol_base;

	int version{current_version};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & version;
	}
};

struct create_storage_reply : storage_request_base {
	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this);
	}
};

struct destroy_storage_reply : storage_request_base {
	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this);
	}
};

struct storage_management_reply : storage_request_base {
	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this);
	}
};

struct response_sequence_number : storage_request_base {
	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this);
	}
};

struct response_records : storage_request_base {
	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this);
	}
};

struct response_data : storage_request_base {
	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this);
	}
};

struct response_commit : storage_request_base {
	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this);
	}
};

using serialisation::type_tag;
using s2c_types =
	typelist<type_tag<server_hello, 1>,
			type_tag<create_storage_reply, 2>,
			type_tag<destroy_storage_reply, 3>,
			type_tag<storage_management_reply, 4>,
			type_tag<response_sequence_number, 5>,
			type_tag<response_records, 6>,
			type_tag<response_data, 7>,
			type_tag<response_commit, 8> >;

}
}

#endif