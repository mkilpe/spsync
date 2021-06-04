#include "connection.hpp"
#include "storage.hpp"

#include <spsync/protocol/error.hpp>
#include <spsync/protocol/server_protocol.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

connection::connection(storage_server_context& c)
: context_(c)
{
}

template<typename T>
void connection::send_packet(T const& p) {
	send(serialisation::asn_der_serialise_choice<protocol::s2c_types>(p));
}

securepath::error connection::on_connect(protocol::client_hello const& p, crypto::public_key_id id) {
	id_ = std::move(id);
	//t: see access
	send_packet(protocol::server_hello{p});

	// no error
	return securepath::error();
}

void connection::handle(protocol::create_storage const& p) {
	securepath::error error;
	try {
		syncs_.emplace(p.sid, context_.acquire_sync(p.sid));
	} catch(securepath::error const& err) {
		LOG_WARN("exception while creating storage: %", err);
		error = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while creating storage: %", ex);
		error = make_error(securepath::errc::unknown_error);
	}
	send_packet(protocol::create_storage_reply{p, std::move(error)});
}

void connection::handle(protocol::destroy_storage const& p) {
	//t: implement
	send_packet(protocol::destroy_storage_reply{p, make_error(securepath::errc::not_implemented)});
}

void connection::handle(protocol::storage_management const& p) {
	//t: implement
	send_packet(protocol::storage_management_reply{p, make_error(securepath::errc::not_implemented)});
}

void connection::handle(protocol::request_sequence_number const& p) {
	securepath::error error;
	sequence_number seq;
	try {
		auto it = syncs_.find(p.sid);
		if(it != syncs_.end()) {
			seq = it->second->current_sequence_number();
		} else {
			error = make_error(protocol::errc::no_such_storage);
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while requesting sequence number for storage: % (sid=%)", err, to_hex(p.sid));
		error = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while requesting sequence number for storage: % (sid=%)", ex, to_hex(p.sid));
		error = make_error(securepath::errc::unknown_error);
	}
	if(error) {
		send_packet(protocol::response_sequence_number{p, error});
	} else {
		send_packet(protocol::response_sequence_number{p, seq});
	}
}

void connection::handle(protocol::request_records const& p) {
	securepath::error error;
	std::deque<chain_block> records;
	sequence_number server_max;
	try {
		auto it = syncs_.find(p.sid);
		if(it != syncs_.end()) {
			records = it->second->get_records(p.start, p.end);
			server_max = it->second->current_sequence_number();
		} else {
			error = make_error(protocol::errc::no_such_storage);
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while requesting records for storage: % (sid=%)", err, to_hex(p.sid));
		error = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while requesting records for storage: % (sid=%)", ex, to_hex(p.sid));
		error = make_error(securepath::errc::unknown_error);
	}
	if(error) {
		send_packet(protocol::response_records{p, std::move(error)});
	} else {
		send_packet(protocol::response_records{p, p.end, server_max, std::move(records)});
	}
}

void connection::handle(protocol::request_data const& p) {
	//t: implement
	send_packet(protocol::response_data{p, make_error(securepath::errc::not_implemented)});
}

void connection::handle(protocol::request_commit const& p) {
	securepath::error error;
	util::result<chain_block> result;
	sequence_number server_max;
	try {
		auto it = syncs_.find(p.sid);
		if(it != syncs_.end()) {
			result = it->second->commit_block(p.record);
			server_max = it->second->current_sequence_number();
		} else {
			result = make_error(protocol::errc::no_such_storage);
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while committing record for storage: % (sid=%)", err, to_hex(p.sid));
		result = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while committing record for storage: % (sid=%)", ex, to_hex(p.sid));
		result = make_error(securepath::errc::unknown_error);
	}
	if(result) {
		send_packet(protocol::response_commit{p, server_max, std::move(result.value())});
	} else {
		send_packet(protocol::response_commit{p, std::move(result.get_error())});
	}
}

}

