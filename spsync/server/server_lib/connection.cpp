#include "connection.hpp"
#include "guarded.hpp"
#include "storage.hpp"

#include <spsync/protocol/error.hpp>
#include <spsync/protocol/server_protocol.hpp>
#include <spsync/protocol/wire_modes.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

connection::connection(storage_server_context& c, storage_data_context& d)
: context_(c)
, data_(d)
{
}

template<typename T>
void connection::send_packet(T const& p) {
	send(serialisation::asn_der_serialise_choice<protocol::s2c_types>(p));
}

storage* connection::find_storage(protocol::storage_id const& sid) {
	storage* ret = nullptr;
	auto it = syncs_.find(sid);
	if(it != syncs_.end()) {
		ret = &*it->second;
	} else {
		LOG_INFO("loading storage {} for user {}", to_hex(sid), id_);
		//t: check the storage exists and you have access to it
		auto handle = context_.acquire_sync(sid);
		syncs_.emplace(sid, handle);
		handle->add_listener(shared_from_this());
		ret = &*handle;
	}
	return ret;
}

securepath::error connection::on_connect(protocol::client_hello const& p, crypto::public_key_id id) {
	LOG_TRACE("on_connect for user {}", id);
	if(p.version != protocol::current_version) {
		LOG_WARN("client {} speaks protocol version {}, this server {}", id, p.version, protocol::current_version);
		return make_error(protocol::errc::invalid_state, "unsupported protocol version");
	}
	id_ = std::move(id);
	//t: see access
	send_packet(protocol::server_hello{p});

	// no error
	return securepath::error();
}

void connection::handle(protocol::create_storage const& p) {
	LOG_TRACE("create_storage for user {}", id_);
	securepath::error error;
	try {
		// a creation always carries modes: the requested ones or the server defaults
		auto handle = context_.acquire_sync(p.sid, protocol::modes_from_wire(p.modes).value_or(storage_modes{}));
		syncs_.emplace(p.sid, handle);
		handle->add_listener(shared_from_this());
	} catch(securepath::error const& err) {
		LOG_WARN("exception while creating storage: {}", err);
		error = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while creating storage: {}", ex.what());
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
	LOG_TRACE("request_sequence_number for user {}", id_);
	securepath::error error;
	sequence_number seq;
	storage_modes smodes{};
	try {
		auto handle = find_storage(p.sid);
		if(handle && context_.is_syncing(p.sid)) {
			// a bootstrapping replica sends the client to another one (plan 5.2)
			LOG_INFO("storage {} is still syncing, client {} told to try another replica", to_hex(p.sid), id_);
			error = make_error(protocol::errc::storage_syncing);
		} else if(handle) {
			smodes = handle->modes();
			auto expected = protocol::modes_from_wire(p.expected_mode, p.expected_amode, p.expected_repl);
			if(expected && !modes_match(*expected, smodes)) {
				LOG_INFO("storage mode mismatch for user {} (sid={})", id_, to_hex(p.sid));
				error = make_error(protocol::errc::storage_mode_mismatch);
			} else {
				seq = handle->current_sequence_number();
			}
		} else {
			LOG_WARN("no such storage: {}", to_hex(p.sid));
			error = make_error(protocol::errc::no_such_storage);
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while requesting sequence number for storage: {} (sid={})", err, to_hex(p.sid));
		error = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while requesting sequence number for storage: {} (sid={})", ex.what(), to_hex(p.sid));
		error = make_error(securepath::errc::unknown_error);
	}
	if(error) {
		send_packet(protocol::response_sequence_number{p, error});
	} else {
		send_packet(protocol::response_sequence_number{p, seq, protocol::to_wire(std::optional<storage_modes>{smodes}), data_.data_endpoints()});
	}
}

void connection::handle(protocol::request_records const& p) {
	LOG_TRACE("request_records for user {}", id_);
	securepath::error error;
	std::deque<chain_block> records;
	sequence_number server_max;
	try {
		auto handle = find_storage(p.sid);
		if(handle) {
			records = handle->get_records(p.start, p.end);
			server_max = handle->current_sequence_number();
		} else {
			LOG_WARN("no such storage: {}", to_hex(p.sid));
			error = make_error(protocol::errc::no_such_storage);
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while requesting records for storage: {} (sid={})", err, to_hex(p.sid));
		error = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while requesting records for storage: {} (sid={})", ex.what(), to_hex(p.sid));
		error = make_error(securepath::errc::unknown_error);
	}
	if(error) {
		send_packet(protocol::response_records{p, std::move(error)});
	} else {
		send_packet(protocol::response_records{p, p.end, server_max, std::move(records)});
	}
}

void connection::handle(protocol::request_commit const& p) {
	LOG_TRACE("request_commit for user {}", id_);
	securepath::error error;
	util::result<chain_block> result;
	std::optional<block_envelope> envelope;
	sequence_number server_max;
	try {
		auto handle = find_storage(p.sid);
		if(handle && context_.is_syncing(p.sid)) {
			result = make_error(protocol::errc::storage_syncing);
		} else if(handle) {
			auto outcome = handle->commit_block(p.record);
			result = std::move(outcome.block);
			envelope = std::move(outcome.envelope);
			server_max = handle->current_sequence_number();
		} else {
			LOG_WARN("no such storage: {}", to_hex(p.sid));
			result = make_error(protocol::errc::no_such_storage);
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while committing record for storage: {} (sid={})", err, to_hex(p.sid));
		result = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while committing record for storage: {} (sid={})", ex.what(), to_hex(p.sid));
		result = make_error(securepath::errc::unknown_error);
	}
	if(result) {
		send_packet(protocol::response_commit{p, server_max, std::move(result.value()), std::move(envelope)});
	} else {
		send_packet(protocol::response_commit{p, std::move(result.get_error())});
	}
}

void connection::handle(protocol::request_data_ticket const& p) {
	LOG_TRACE("request_data_ticket for user {} [data_id={}]", id_, to_hex(p.data_id));
	auto issued = guarded("issuing a data ticket", p.sid, [&]() -> util::result<issued_ticket> {
		auto handle = find_storage(p.sid);
		if(!handle) {
			return make_error(protocol::errc::no_such_storage);
		}
		if(context_.is_syncing(p.sid)) {
			// the record naming the data may not have arrived here yet
			return make_error(protocol::errc::storage_syncing);
		}
		return data_.issue_data_ticket(*handle, p.data_id, id_, p.right);
	});
	if(issued) {
		send_packet(protocol::response_data_ticket{p, std::move(issued.value().ticket), std::move(issued.value().holders)});
	} else {
		LOG_INFO("no data ticket for user {}: {}", id_, issued.get_error());
		send_packet(protocol::response_data_ticket{p, issued.get_error()});
	}
}

void connection::notify(protocol::storage_id const& sid, chain_block const& c, std::optional<block_envelope> const& env) {
	send_packet(protocol::notify_record{sid, c, env});
}

void connection::notify_data(protocol::storage_id const& sid, data_id const& id, bool complete) {
	send_packet(protocol::notify_data{sid, id, complete});
}

}
