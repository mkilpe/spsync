#pragma once

#include "net_connection.hpp"

#include <spsync/comm/comm.hpp>
#include <spsync/protocol/client_protocol.hpp>
#include <spsync/protocol/error.hpp>
#include <spsync/protocol/server_protocol.hpp>
#include <spsync/protocol/wire_modes.hpp>

#include <securepath/crypto/random.hpp>
#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/network/encryption/framing.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

struct network_connection_impl : network::encrypted_connection {
	network_connection_impl(network::context& context, event_system::event_handler& handler)
	: encrypted_connection(context)
	, handler(handler)
	{}

	~network_connection_impl() {
		encrypted_connection::close();
	}

	template<typename T>
	void send(T const& p) {
		encrypted_connection::send(serialisation::asn_der_serialise_choice<protocol::c2s_types>(p));
	}

	void close(error const& err = {}) {
		LOG_TRACE("closing storage network connection");
		encrypted_connection::close();
		on_disconnected(err);
	}

	void on_connected() override {
		LOG_TRACE("storage network connection connected, sending client_hello...");
		hello_done = false;
		deser.clear();
		send(protocol::client_hello{});
	}

	void on_disconnected(securepath::error const& error) override {
		LOG_INFO("storage network connection disconnected: {}", error);
		handler.emit<events::on_disconnect>(error);
		for(auto&& v : attached_comms) {
			v.second->on_disconnected(error);
		}
	}

	void on_sent(std::size_t bytes) override {

	}

	void on_received(octet_span s) override {
		deser.handle(s,
			[this](auto const& packet) {
				this->handle(packet);
			});
	}

	void handle(protocol::server_hello const& p) {
		if(p.error) {
			LOG_WARN("server responded with error: {}", p.error);
			close(protocol::to_error(p.error));
		} else {
			hello_done = true;
			// notify higher level that we are connected now
			handler.emit<events::on_connect>();
			for(auto&& v : attached_comms) {
				v.second->on_connected();
			}
		}
	}

	void handle(protocol::create_storage_reply const& p) {
		error err;
		if(p.error) {
			LOG_INFO("failed to create storage ({}) on server: {}", to_hex(p.sid), p.error);
			err = protocol::to_error(p.error);
		}
		handler.emit<events::on_create_storage>(p.sid, err);
	}

	void handle(protocol::destroy_storage_reply const& p) {

	}

	void handle(protocol::storage_management_reply const& p) {

	}

	template<typename Packet>
	void handle(Packet const& p) {
		std::unique_lock lock{mutex};
		auto it = attached_comms.find(p.sid);
		if(it != attached_comms.end()) {
			it->second->handle(p);
		}
	}

	void attach(storage_id const& id) {
		std::unique_lock lock{mutex};
		auto node = comms.extract(id);
		if(node) {
			auto res = attached_comms.insert(std::move(node));
			if(hello_done && res.inserted) {
				res.position->second->on_connected();
			}
		}
	}

	request_handle fetch_sequence_number(storage_id id, std::optional<storage_modes> expected_modes = {}) {
		auto h = ++call_id;
		auto const w = protocol::to_wire(expected_modes);
		send(protocol::request_sequence_number{h, std::move(id), w.mode, w.amode, w.repl});
		return h;
	}

	request_handle fetch_records(storage_id id, sequence_number start, sequence_number end) {
		auto h = ++call_id;
		send(protocol::request_records{h, std::move(id), start, end});
		return h;
	}

	request_handle request_data_ticket(storage_id id, octet_vector data_id, data_right right) {
		auto h = ++call_id;
		send(protocol::request_data_ticket{h, std::move(id), std::move(data_id), static_cast<std::uint32_t>(right)});
		return h;
	}

	request_handle commit_record(storage_id id, chain_block record) {
		auto h = ++call_id;
		send(protocol::request_commit{h, std::move(id), std::move(record)});
		return h;
	}

public:
	mutable std::mutex mutex;
	event_system::event_handler& handler;
	std::atomic<std::uint32_t> call_id{};
	// a record may be up to max_record_size_range.highest and a batch is budgeted by the server: the
	// transport frame is the bound of a message, not the deserialiser's 1 MiB default
	serialisation::packet_deserialiser<protocol::s2c_types> deser{network::max_frame_size};
	std::map<storage_id, std::unique_ptr<comm>> comms;
	std::map<storage_id, std::unique_ptr<comm>> attached_comms;
	bool hello_done{};
};

}

