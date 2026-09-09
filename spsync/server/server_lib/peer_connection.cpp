#include "peer_connection.hpp"
#include "storage.hpp"

#include <spsync/protocol/error.hpp>

#include <securepath/crypto/error.hpp>
#include <securepath/log/log.hpp>

#include <map>
#include <securepath/util/conversions.hpp>

#include <algorithm>

namespace securepath::sync {

peer_connection::peer_connection(network::context& c, storage_server_context& sctx,
	network::handshake_data hdata, std::shared_ptr<network::encrypted_server> server)
: encrypted_connection(c, std::move(hdata), std::move(server))
, sctx_(sctx)
{
	LOG_TRACE("constructing peer_connection {}", static_cast<void const*>(this));
}

peer_connection::~peer_connection() {
	LOG_TRACE("destructing peer_connection {}", static_cast<void const*>(this));
	encrypted_connection::close();
}

void peer_connection::connect_peer(peer_config const& peer, std::chrono::seconds timeout) {
	{
		std::unique_lock lock{mutex_};
		expected_ = peer;
	}
	LOG_INFO("connecting to peer {}", peer);
	connect(peer.host, peer.port, timeout);
}

std::optional<crypto::public_key_id> peer_connection::peer_id() const {
	std::unique_lock lock{mutex_};
	return peer_id_;
}

std::vector<origin_head> peer_connection::heads_of_peer(protocol::storage_id const& sid) const {
	std::unique_lock lock{mutex_};
	std::vector<origin_head> ret;
	auto it = peer_heads_.find(sid);
	if(it != peer_heads_.end()) {
		ret = it->second;
	}
	return ret;
}

void peer_connection::set_connected_handler(std::function<void()> f) {
	std::unique_lock lock{mutex_};
	on_connected_ = std::move(f);
}

void peer_connection::set_disconnect_handler(std::function<void(securepath::error const&)> f) {
	std::unique_lock lock{mutex_};
	on_disconnect_ = std::move(f);
}

void peer_connection::push(protocol::push_records const& p) {
	bool ready{};
	{
		std::unique_lock lock{mutex_};
		ready = peer_id_.has_value();
	}
	if(ready) {
		send_packet(p);
	}
}

void peer_connection::announce_heads() {
	bool ready{};
	{
		std::unique_lock lock{mutex_};
		ready = peer_id_.has_value();
	}
	if(ready) {
		send_our_heads();
	}
}

void peer_connection::terminate(securepath::error const& err) {
	encrypted_connection::close();
	on_disconnected(err);
}

/// the transport key must belong to a configured peer (and to the dialed peer when outgoing)
bool peer_connection::authenticate_transport() {
	auto key = remote_key_id();
	if(!key) {
		LOG_WARN("peer connection without a transport key");
		return false;
	}
	std::unique_lock lock{mutex_};
	if(expected_) {
		if(*key != expected_->key) {
			LOG_WARN("peer key does not match the configuration [peer={}, got={}]", *expected_, *key);
			return false;
		}
		return true;
	}
	auto const& peers = sctx_.identity().peers;
	if(std::ranges::find(peers, *key, &peer_config::key) == peers.end()) {
		LOG_WARN("connection from an unknown peer [key={}]", *key);
		return false;
	}
	return true;
}

void peer_connection::on_connected() {
	if(!authenticate_transport()) {
		terminate(make_error(protocol::errc::invalid_client_key));
	} else {
		send_hello();
	}
}

void peer_connection::on_disconnected(securepath::error const& error) {
	LOG_TRACE("peer disconnected ({}): {}", peer_id().value_or(crypto::public_key_id{}), error);
	std::function<void(securepath::error const&)> handler;
	{
		std::unique_lock lock{mutex_};
		peer_id_.reset();
		handler = on_disconnect_;
	}
	if(handler) {
		handler(error);
	}
}

void peer_connection::on_received(octet_span s) {
	try {
		deser_.handle(s, std::ref(*this));
	} catch(error const& err) {
		LOG_WARN("error while handling peer packet [err={}]", err);
		terminate(err);
	} catch(...) {
		LOG_WARN("unknown exception while handling peer packet");
		terminate(make_error(protocol::errc::invalid_state));
	}
}

void peer_connection::send_packet(auto const& packet) {
	send(serialisation::asn_der_serialise_choice<protocol::s2s_types>(packet));
}

void peer_connection::send_hello() {
	send_packet(protocol::peer_hello{sctx_.identity().server_id});
}

/// announce the heads of every replicated open storage (the 3.4 exchange)
void peer_connection::send_our_heads() {
	for(auto const& sid : sctx_.replicated_storages()) {
		auto handle = sctx_.find_open_sync(sid);
		if(handle) {
			send_packet(protocol::peer_heads{sid, handle->heads(), handle->modes()});
		}
	}
}

bool peer_connection::check_ready(char const* what) {
	std::unique_lock lock{mutex_};
	if(!peer_id_) {
		LOG_WARN("{} before peer_hello", what);
	}
	return peer_id_.has_value();
}

void peer_connection::operator()(protocol::peer_hello const& p) {
	// the claimed identity must be the authenticated transport key
	if(p.server_id != remote_key_id().value_or(crypto::public_key_id{})) {
		LOG_WARN("peer hello does not match the transport key [claimed={}]", p.server_id);
		terminate(make_error(protocol::errc::invalid_client_key));
	} else if(p.version != protocol::s2s_current_version) {
		LOG_WARN("unsupported s2s protocol version {} from {}", p.version, p.server_id);
		terminate(make_error(protocol::errc::invalid_state));
	} else {
		LOG_INFO("peer connected: {}", p.server_id);
		std::function<void()> connected;
		{
			std::unique_lock lock{mutex_};
			peer_id_ = p.server_id;
			connected = on_connected_;
		}
		if(connected) {
			connected();
		}
		// the handshake verified the peer's key against the root: its signed assignments verify from now on
		if(auto key = remote_public_key()) {
			sctx_.trust_peer_key(*key);
		}
		send_our_heads();
	}
}

void peer_connection::operator()(protocol::peer_heads const& p) {
	if(check_ready("peer heads")) {
		LOG_TRACE("peer heads [sid={}, heads={}]", to_hex(p.sid), p.heads.size());
		{
			std::unique_lock lock{mutex_};
			peer_heads_[p.sid] = p.heads;
		}
		start_pulls(p);
	}
}

/// pull every origin the peer is ahead on (plan 4.4); the peer does the same for the
/// origins we are ahead on when it receives our heads
void peer_connection::start_pulls(protocol::peer_heads const& p) {
	auto handle = sctx_.acquire_replica(p.sid, protocol::peer_modes(p.modes));
	if(handle && handle->modes().replication == replication_mode::weak) {
		auto const& own = sctx_.identity().server_id;
		bool behind = false;
		for(auto const& head : p.heads) {
			if(head.origin != own) {
				auto const known = handle->known_origin_seq(head.origin);
				if(known < head.block.sequence) {
					behind = true;
					request_pull(p.sid, head.origin, known + 1, head.block.sequence);
				}
			}
		}
		if(!behind) {
			sctx_.note_caught_up(p.sid);
		}
	}
}

/// re-run the pulls the last announced heads call for (after a signer key arrived)
void peer_connection::resume_pulls() {
	std::map<protocol::storage_id, std::vector<origin_head>> heads;
	{
		std::unique_lock lock{mutex_};
		heads = peer_heads_;
	}
	for(auto const& [sid, h] : heads) {
		if(auto handle = sctx_.find_open_sync(sid)) {
			start_pulls(protocol::peer_heads{sid, h, handle->modes()});
		}
	}
}

/**
 * Apply pulled or pushed envelopes; a record whose signer we do not know is not lost:
 * the peer that holds the record holds the signer's key too, ask for it (plan 5.2) and
 * the next pull round applies the record
 */
void peer_connection::apply_envelopes(std::shared_ptr<storage> const& handle,
	std::deque<block_envelope> const& envelopes, char const* what)
{
	for(auto const& env : envelopes) {
		if(auto err = handle->apply_foreign(env)) {
			LOG_WARN("failed to apply {} record [origin={}, err={}]", what, env.origin(), err);
			if(err.code() == make_error_code(protocol::errc::unknown_signer)) {
				if(auto signer = env.block().auth().signature_issuer()) {
					request_signer_key(*signer);
				}
			} else if(err.code() == make_error_code(crypto::errc::no_such_key)) {
				// an origin we never met (a transitive one while bootstrapping): the peer
				// serving its records verified them, so it holds the key
				request_signer_key(env.origin());
			}
		}
	}
}

void peer_connection::request_signer_key(crypto::public_key_id const& id) {
	bool ask{};
	protocol::call_id cid{};
	{
		std::unique_lock lock{mutex_};
		ask = std::ranges::find(key_requests_, id, &decltype(key_requests_)::value_type::second) == key_requests_.end();
		if(ask) {
			cid = next_cid_++;
			key_requests_[cid] = id;
		}
	}
	if(ask) {
		LOG_INFO("asking peer for the key of record signer {}", id);
		send_packet(protocol::request_key{cid, id});
	}
}

void peer_connection::operator()(protocol::request_key const& p) {
	if(check_ready("request_key")) {
		auto key = sctx_.find_key(p.key);
		LOG_TRACE("request_key [key={}, held={}]", p.key, key.has_value());
		send_packet(protocol::response_key{p.cid, std::move(key)});
	}
}

void peer_connection::operator()(protocol::response_key const& p) {
	LOG_TRACE("response_key [held={}]", p.key.has_value());
	if(check_ready("response_key")) {
		// the request is done either way; a negative answer leaves the signer askable again
		std::optional<crypto::public_key_id> asked;
		{
			std::unique_lock lock{mutex_};
			auto it = key_requests_.find(p.cid);
			if(it != key_requests_.end()) {
				asked = it->second;
				key_requests_.erase(it);
			}
		}
		if(!asked) {
			LOG_WARN("response_key for an unknown request [cid={}]", p.cid);
		} else if(p.key && p.key->id() == *asked) {
			sctx_.learn_signer_key(*p.key);
			resume_pulls();
		} else if(p.key) {
			LOG_WARN("peer sent another key than asked for [asked={}, got={}]", *asked, p.key->id());
		} else {
			LOG_INFO("peer does not hold the key of signer {} either", *asked);
		}
	}
}

void peer_connection::request_pull(protocol::storage_id const& sid, crypto::public_key_id const& origin,
	sequence_number from, sequence_number to) {
	bool start{};
	protocol::call_id cid{};
	{
		std::unique_lock lock{mutex_};
		start = pulling_.insert({sid, origin.data()}).second;
		cid = next_cid_++;
	}
	if(start) {
		LOG_TRACE("pulling origin {} [{}..{}] for storage {}", origin, from, to, to_hex(sid));
		send_packet(protocol::pull_records{cid, sid, origin, from, to});
	}
}

void peer_connection::operator()(protocol::pull_records const& p) {
	if(check_ready("pull_records")) {
		auto handle = sctx_.acquire_replica(p.sid, {});
		if(!handle) {
			send_packet(protocol::not_replicating{0, p.sid});
			send_packet(protocol::response_envelopes{p, make_error(protocol::errc::no_such_storage)});
		} else {
			// every origin, the own one included, is served by its assignments: the puller
			// measures progress on the origin's sequences, so foreign records committed in
			// between must not ride along (they made the pull stall past a batch of them)
			send_packet(protocol::response_envelopes{p, handle->known_origin_seq(p.origin)
				, handle->get_envelopes_by_origin(p.origin, p.from, p.to)});
		}
	}
}

void peer_connection::operator()(protocol::response_envelopes const& p) {
	if(check_ready("response_envelopes")) {
		{
			std::unique_lock lock{mutex_};
			pulling_.erase({p.sid, p.origin.data()});
		}
		LOG_TRACE("response_envelopes [sid={}, origin={}, envelopes={}]", to_hex(p.sid), p.origin, p.envelopes.size());
		auto handle = sctx_.find_open_sync(p.sid);
		if(handle && !p.error) {
			apply_envelopes(handle, p.envelopes, "pulled");
			// keep pulling while the peer holds more of the origin AND this batch made
			// progress (no progress means the applies failed, retried on the next tick)
			auto const known = handle->known_origin_seq(p.origin);
			bool const progressed = !p.envelopes.empty()
				&& known >= p.envelopes.back().block().sequence();
			if(progressed && p.origin_max.is_valid() && known < p.origin_max) {
				request_pull(p.sid, p.origin, known + 1, p.origin_max);
			} else if(progressed) {
				sctx_.note_caught_up(p.sid);
			}
		}
	}
}

void peer_connection::operator()(protocol::push_records const& p) {
	if(check_ready("push_records")) {
		auto handle = sctx_.acquire_replica(p.sid, protocol::peer_modes(p.modes));
		if(!handle || handle->modes().replication == replication_mode::none) {
			send_packet(protocol::not_replicating{0, p.sid});
		} else {
			LOG_TRACE("peer pushed {} records for storage {}", p.envelopes.size(), to_hex(p.sid));
			// pushes are fire and forget; anti-entropy reconciles later (plan 4.4)
			apply_envelopes(handle, p.envelopes, "pushed");
		}
	}
}

void peer_connection::operator()(protocol::not_replicating const& p) {
	LOG_INFO("peer does not replicate storage {}", to_hex(p.sid));
}

}
