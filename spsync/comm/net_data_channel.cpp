#include "net_data_channel.hpp"

#include <spsync/protocol/data_protocol.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>

#include <atomic>
#include <map>
#include <mutex>

namespace securepath::sync {
namespace {

/// the answer to a manifest: the holder's have octets, or an error and whether it was
/// the transport that failed (try the next holder) or the holder that refused (final)
using manifest_handler = std::move_only_function<void(util::result<octet_vector>, bool transport_failure)>;
using chunk_handler = data_channel::piece_callback;

std::string endpoint_name(data_endpoint const& e) {
	return e.host + ":" + std::to_string(e.port);
}

/// the connection to one data server
class data_link : public network::encrypted_connection {
public:
	data_link(network::context& context, data_endpoint endpoint)
	: encrypted_connection(context)
	, endpoint_(std::move(endpoint))
	{}

	~data_link() {
		encrypted_connection::close();
	}

	void start(std::chrono::seconds timeout) {
		LOG_TRACE("connecting to data server {}", endpoint_name(endpoint_));
		connect(endpoint_.host, endpoint_.port, timeout);
	}

	bool dead() const {
		std::unique_lock lock{mutex_};
		return dead_;
	}

	void shutdown() {
		encrypted_connection::close();
		fail_all(make_error(securepath::errc::invalid_state, "data channel closed"));
	}

	void send_manifest(data_ticket const& ticket, data_manifest const& manifest, manifest_handler handler) {
		auto const cid = ++call_id_;
		post(cid, protocol::upload_data_manifest{cid, ticket, manifest}, manifests_, std::move(handler)
			, [](manifest_handler& h, error const& err) { h(util::result<octet_vector>{err}, true); });
	}

	void send_piece(octet_vector const& sid, data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, octet_vector bytes, chunk_handler handler) {
		auto const cid = ++call_id_;
		post(cid, protocol::upload_data_chunk{cid, sid, id, chunk_no, offset, std::move(bytes)}, chunks_, std::move(handler)
			, [](chunk_handler& h, error const& err) { h(err); });
	}

private:
	/// remember the handler and send the packet, or keep it until the hello is answered;
	/// on a dead link the handler is failed at once
	template<typename Packet, typename Handler, typename Fail>
	void post(protocol::call_id cid, Packet const& packet, std::map<protocol::call_id, Handler>& calls, Handler handler, Fail fail) {
		auto bytes = serialisation::asn_der_serialise_choice<protocol::c2d_types>(packet);
		std::unique_lock lock{mutex_};
		if(dead_) {
			auto const err = failure_;
			lock.unlock();
			fail(handler, err);
		} else {
			calls.emplace(cid, std::move(handler));
			// sent with the lock held: the pieces of a chunk must leave in the order they
			// were posted, also while the outbox is being flushed
			if(ready_) {
				encrypted_connection::send(bytes);
			} else {
				outbox_.push_back(std::move(bytes));
			}
		}
	}

	void on_connected() override {
		auto const remote = remote_key_id();
		if(endpoint_.key.is_valid() && remote != endpoint_.key) {
			LOG_WARN("data server {} authenticated with another key than the grant names", endpoint_name(endpoint_));
			encrypted_connection::close();
			fail_all(make_error(protocol::errc::invalid_client_key, "data server key mismatch"));
		} else {
			deser_.clear();
			encrypted_connection::send(serialisation::asn_der_serialise_choice<protocol::c2d_types>(protocol::data_hello{}));
		}
	}

	void on_disconnected(securepath::error const& err) override {
		LOG_INFO("data server {} disconnected: {}", endpoint_name(endpoint_), err);
		fail_all(err ? err : make_error(securepath::errc::invalid_state, "data connection closed"));
	}

	void on_received(octet_span s) override {
		try {
			deser_.handle(s, [this](auto const& packet) { this->handle(packet); });
		} catch(std::exception const& ex) {
			LOG_WARN("bad packet from data server {}: {}", endpoint_name(endpoint_), ex.what());
			encrypted_connection::close();
			fail_all(make_error(securepath::errc::invalid_data, "bad packet from the data server"));
		}
	}

	void handle(protocol::data_hello_reply const& p) {
		if(p.error) {
			encrypted_connection::close();
			fail_all(protocol::to_error(p.error));
		} else {
			std::unique_lock lock{mutex_};
			ready_ = true;
			for(auto const& bytes : outbox_) {
				encrypted_connection::send(bytes);
			}
			outbox_.clear();
		}
	}

	void handle(protocol::upload_data_manifest_reply const& p) {
		auto handler = take(manifests_, p.cid);
		if(handler) {
			if(p.error) {
				handler(util::result<octet_vector>{protocol::to_error(p.error)}, false);
			} else {
				handler(util::result<octet_vector>{p.have}, false);
			}
		}
	}

	void handle(protocol::upload_data_chunk_reply const& p) {
		auto handler = take(chunks_, p.cid);
		if(handler) {
			handler(p.error ? std::optional<error>{protocol::to_error(p.error)} : std::nullopt);
		}
	}

	template<typename Handler>
	Handler take(std::map<protocol::call_id, Handler>& calls, protocol::call_id cid) {
		Handler ret;
		std::unique_lock lock{mutex_};
		auto it = calls.find(cid);
		if(it != calls.end()) {
			ret = std::move(it->second);
			calls.erase(it);
		}
		return ret;
	}

	/// the link is gone: every call still out gets the error, new ones too
	void fail_all(error const& err) {
		std::map<protocol::call_id, manifest_handler> manifests;
		std::map<protocol::call_id, chunk_handler> chunks;
		{
			std::unique_lock lock{mutex_};
			if(!dead_) {
				dead_ = true;
				failure_ = err;
			}
			manifests.swap(manifests_);
			chunks.swap(chunks_);
			outbox_.clear();
		}
		for(auto& [cid, handler] : manifests) {
			handler(util::result<octet_vector>{err}, true);
		}
		for(auto& [cid, handler] : chunks) {
			handler(err);
		}
	}

private:
	data_endpoint const endpoint_;
	std::atomic<protocol::call_id> call_id_{0};
	serialisation::packet_deserialiser<protocol::d2c_types> deser_;

	mutable std::mutex mutex_;
	std::map<protocol::call_id, manifest_handler> manifests_;
	std::map<protocol::call_id, chunk_handler> chunks_;
	/// packets waiting for the hello to be answered
	std::vector<octet_vector> outbox_;
	error failure_;
	bool ready_{};
	bool dead_{};
};

}

class net_data_channel::impl : public std::enable_shared_from_this<impl> {
public:
	impl(network::context& context, ticket_source tickets, std::chrono::seconds timeout)
	: context_(context)
	, tickets_(std::move(tickets))
	, timeout_(timeout)
	{}

	/// one attempt to open an upload: the grant and how far down its holder list we are
	struct attempt {
		data_descriptor descriptor;
		data_manifest manifest;
		data_grant grant;
		open_callback callback;
		std::size_t holder{};
	};

	void open_upload(data_descriptor const& descriptor, data_manifest const& manifest, open_callback cb) {
		auto att = std::make_shared<attempt>(attempt{descriptor, manifest, {}, std::move(cb)});
		std::weak_ptr<impl> weak = shared_from_this();
		tickets_(descriptor, data_right::upload, [weak, att](util::result<data_grant> grant) {
			auto self = weak.lock();
			if(!self) {
				att->callback(util::result<have_bitmap>{make_error(securepath::errc::invalid_state, "data channel closed")});
			} else if(!grant) {
				att->callback(util::result<have_bitmap>{grant.get_error()});
			} else {
				att->grant = std::move(grant.value());
				self->try_holder(att, make_error(securepath::errc::no_such_data, "the grant names no data server"));
			}
		});
	}

	/// send the manifest to the attempt's current holder; last_error is the answer when none is left
	void try_holder(std::shared_ptr<attempt> const& att, error const& last_error) {
		if(att->holder >= att->grant.holders.size()) {
			att->callback(util::result<have_bitmap>{last_error});
		} else {
			auto const endpoint = att->grant.holders[att->holder];
			auto link = acquire_link(endpoint);
			std::weak_ptr<impl> weak = shared_from_this();
			link->send_manifest(att->grant.ticket, att->manifest, [weak, att, link](util::result<octet_vector> have, bool transport_failure) {
				auto self = weak.lock();
				if(have && self) {
					self->remember_upload(att->grant.ticket, link);
					att->callback(util::result<have_bitmap>{have_bitmap{att->descriptor.chunk_count(), std::move(have.value())}});
				} else if(transport_failure && self) {
					// RD13: a holder that is down is the next entry
					++att->holder;
					self->try_holder(att, have.get_error());
				} else {
					att->callback(util::result<have_bitmap>{have ? make_error(securepath::errc::invalid_state, "data channel closed") : have.get_error()});
				}
			});
		}
	}

	void send_piece(data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, octet_vector bytes, piece_callback cb) {
		std::shared_ptr<data_link> link;
		octet_vector sid;
		{
			std::unique_lock lock{mutex_};
			auto it = uploads_.find(id);
			if(it != uploads_.end()) {
				link = it->second.link;
				sid = it->second.sid;
			}
		}
		if(link) {
			link->send_piece(sid, id, chunk_no, offset, std::move(bytes), std::move(cb));
		} else {
			cb(make_error(protocol::errc::no_such_upload, "no upload opened for the data"));
		}
	}

	void close() {
		std::map<std::string, std::shared_ptr<data_link>> links;
		{
			std::unique_lock lock{mutex_};
			links.swap(links_);
			uploads_.clear();
		}
		for(auto& [name, link] : links) {
			link->shutdown();
		}
	}

private:
	/// the live connection to the data server, a new one when there is none
	std::shared_ptr<data_link> acquire_link(data_endpoint const& endpoint) {
		std::shared_ptr<data_link> link;
		bool is_new = false;
		{
			std::unique_lock lock{mutex_};
			auto& slot = links_[endpoint_name(endpoint)];
			is_new = !slot || slot->dead();
			if(is_new) {
				slot = std::make_shared<data_link>(context_, endpoint);
			}
			link = slot;
		}
		if(is_new) {
			link->start(timeout_);
		}
		return link;
	}

	void remember_upload(data_ticket const& ticket, std::shared_ptr<data_link> link) {
		std::unique_lock lock{mutex_};
		uploads_[ticket.data()] = upload{ticket.storage_id(), std::move(link)};
	}

private:
	struct upload {
		octet_vector sid;
		std::shared_ptr<data_link> link;
	};

	network::context& context_;
	ticket_source const tickets_;
	std::chrono::seconds const timeout_;

	std::mutex mutex_;
	/// one connection per data server, by host:port
	std::map<std::string, std::shared_ptr<data_link>> links_;
	/// where the chunks of an opened upload go
	std::map<data_id, upload> uploads_;
};

net_data_channel::net_data_channel(network::context& context, ticket_source tickets, std::chrono::seconds timeout)
: impl_(std::make_shared<impl>(context, std::move(tickets), timeout))
{
}

net_data_channel::~net_data_channel() {
	close();
}

void net_data_channel::open_upload(data_descriptor const& descriptor, data_manifest const& manifest, open_callback cb) {
	impl_->open_upload(descriptor, manifest, std::move(cb));
}

void net_data_channel::send_piece(data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, octet_vector bytes, piece_callback cb) {
	impl_->send_piece(id, chunk_no, offset, std::move(bytes), std::move(cb));
}

void net_data_channel::close() {
	impl_->close();
}

}
