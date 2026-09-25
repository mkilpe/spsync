#include "peer_connection.hpp"
#include "guarded.hpp"
#include "storage.hpp"

#include <spsync/protocol/error.hpp>

#include <securepath/crypto/error.hpp>
#include <securepath/log/log.hpp>

#include <securepath/util/conversions.hpp>

#include <map>

#include <algorithm>

namespace securepath::sync {

peer_connection::peer_connection(network::context& c, storage_server_context& sctx, storage_data_context& dctx,
	network::handshake_data hdata, std::shared_ptr<network::encrypted_server> server)
: encrypted_connection(c, std::move(hdata), std::move(server))
, sctx_(sctx)
, dctx_(dctx)
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
		ret = it->second.heads;
	}
	return ret;
}

bool peer_connection::origin_diverged(protocol::storage_id const& sid, crypto::public_key_id const& origin) const {
	std::unique_lock lock{mutex_};
	return diverged_.contains({sid, origin.data()});
}

void peer_connection::set_connected_handler(std::function<void()> f) {
	std::unique_lock lock{mutex_};
	on_connected_ = std::move(f);
}

void peer_connection::set_disconnect_handler(std::function<void(securepath::error const&)> f) {
	std::unique_lock lock{mutex_};
	on_disconnect_ = std::move(f);
}

/// the hello exchange is done and the link is of the kind wanted: a replication peer
/// (the record exchange, the announcements record servers make to each other) or a
/// separate data server (releases, copies to hold)
bool peer_connection::ready_as(bool data_server_link) const {
	std::unique_lock lock{mutex_};
	return peer_id_.has_value() && data_server_link_ == data_server_link;
}

bool peer_connection::is_data_server_link() const {
	return ready_as(true);
}

void peer_connection::push(protocol::push_records const& p) {
	if(ready_as(false)) {
		send_packet(p);
	}
}

void peer_connection::announce_heads() {
	if(ready_as(false)) {
		send_our_heads();
	}
}

void peer_connection::announce(protocol::announce_data const& p) {
	if(ready_as(false)) {
		send_packet(p);
	}
}

void peer_connection::release(protocol::release_data const& p) {
	if(ready_as(true)) {
		send_packet(p);
	}
}

void peer_connection::operator()(protocol::release_data const& p) {
	// record servers tell data servers, nobody tells a record server
	LOG_WARN("release_data for storage {} on a record server, ignored", to_hex(p.sid));
}

bool peer_connection::replicate(protocol::replicate_data const& p) {
	bool const ready = is_data_server_link();
	if(ready) {
		send_packet(p);
	}
	return ready;
}

void peer_connection::operator()(protocol::replicate_data const& p) {
	LOG_WARN("replicate_data for storage {} on a record server, ignored", to_hex(p.sid));
}

void peer_connection::operator()(protocol::response_replica_ticket const& p) {
	LOG_WARN("response_replica_ticket for storage {} on a record server, ignored", to_hex(p.sid));
}

/// a data server asks for the ticket of a pull this server told it to make (RD13): the
/// ticket is issued to the key the link authenticated with, and to a data server only
void peer_connection::operator()(protocol::request_replica_ticket const& p) {
	if(!is_data_server_link()) {
		LOG_WARN("request_replica_ticket for storage {} from a peer that is no data server, ignored", to_hex(p.sid));
	} else {
		auto issued = guarded("issuing a replica ticket", p.sid, [&] {
			return dctx_.issue_replica_ticket(p.sid, p.data_id, peer_id().value_or(crypto::public_key_id{}));
		});
		if(issued) {
			send_packet(protocol::response_replica_ticket{p, std::move(issued.value().ticket), std::move(issued.value().holders)});
		} else {
			LOG_INFO("no replica ticket for {} [data_id={}]: {} (sid={})", peer_id().value_or(crypto::public_key_id{})
				, to_hex(p.data_id), issued.get_error(), to_hex(p.sid));
			send_packet(protocol::response_replica_ticket{p, issued.get_error()});
		}
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
		// a separate data server announcing what it holds (RD12/RD13)
		data_server_link_ = dctx_.is_data_server(*key);
		if(!data_server_link_) {
			LOG_WARN("connection from an unknown peer [key={}]", *key);
		}
		return data_server_link_;
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
			send_packet(protocol::peer_heads{sid, handle->heads(), handle->modes(), handle->history_samples()});
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

/// the record exchange is between replication peers: a data server link takes no part in it
bool peer_connection::check_peer(char const* what) {
	bool ok = check_ready(what);
	std::unique_lock lock{mutex_};
	if(ok && data_server_link_) {
		LOG_WARN("{} on a data server link, ignored", what);
		ok = false;
	}
	return ok;
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
		bool data_server_link{};
		{
			std::unique_lock lock{mutex_};
			data_server_link = data_server_link_;
		}
		if(!data_server_link) {
			send_our_heads();
			// RD13: the availability tables are transient, a link that comes up gets the whole view
			for(auto const& announcement : dctx_.own_data_announcements()) {
				send_packet(announcement);
			}
		}
	}
}

void peer_connection::operator()(protocol::announce_data const& p) {
	if(check_ready("data announcement")) {
		// a record server announces its own data role only: nobody speaks for another holder
		if(p.holder == peer_id().value_or(crypto::public_key_id{})) {
			dctx_.data_announced(p);
		} else {
			LOG_WARN("data announcement for holder {} from another peer, ignored", p.holder);
		}
	}
}

void peer_connection::operator()(protocol::peer_heads const& p) {
	if(check_peer("peer heads")) {
		LOG_TRACE("peer heads [sid={}, heads={}]", to_hex(p.sid), p.heads.size());
		{
			std::unique_lock lock{mutex_};
			peer_heads_[p.sid] = p;
		}
		start_pulls(p);
	}
}

namespace {

/// the peer's samples of one origin's history, none when it announced no samples for it
origin_samples const* samples_of(protocol::peer_heads const& p, crypto::public_key_id const& origin) {
	auto it = std::ranges::find(p.samples, origin, &origin_samples::origin);
	return it == p.samples.end() ? nullptr : &*it;
}

}

/// pull every origin the peer is ahead on (plan 4.4); the peer does the same for the
/// origins we are ahead on when it receives our heads
void peer_connection::start_pulls(protocol::peer_heads const& p) {
	auto handle = sctx_.acquire_replica(p.sid, protocol::peer_modes(p.modes));
	if(handle && handle->modes().replication == replication_mode::weak) {
		bool behind = false;
		for(auto const& head : p.heads) {
			behind = pull_origin(handle, p, head) || behind;
		}
		if(!behind) {
			sctx_.note_caught_up(p.sid);
		}
	}
}

/**
 * Pull one origin when the peer is ahead on it and the histories agree (plan 5.3): the
 * pull starts after the newest record we hold of the origin, the stored head or the
 * newest common sample. A history that parts from ours is not pulled (the records would
 * conflict with held ones), nor is our own origin. True when a pull went out.
 */
bool peer_connection::pull_origin(std::shared_ptr<storage> const& handle, protocol::peer_heads const& p, origin_head const& head) {
	auto const* samples = samples_of(p, head.origin);
	auto const div = samples ? handle->find_divergence(*samples) : divergence{};
	note_divergence(p.sid, head.origin, div.diverged());
	bool wanted = false;
	if(handle->condemned(head.origin)) {
		LOG_TRACE("nothing of condemned origin {} is pulled (rsid={})", head.origin, to_hex(p.sid));
	} else if(div.diverged()) {
		LOG_WARN("the history of origin {} at peer {} parts from ours between sequences {} and {}: not pulled (rsid={})"
			, head.origin, peer_id().value_or(crypto::public_key_id{}), div.last_common, div.first_divergent, to_hex(p.sid));
		// the record it holds there is the proof the origin assigned the sequence twice
		// (plan 5.4): asked for on its own, refused on arrival and kept as evidence
		request_pull(p.sid, head.origin, div.first_divergent, div.first_divergent);
	} else if(head.origin != sctx_.identity().server_id) {
		auto const plan = plan_pull(handle->known_origin_seq(head.origin), head.block.sequence, div);
		wanted = plan.wanted();
		if(wanted) {
			request_pull(p.sid, head.origin, plan.from, plan.to);
		}
	}
	return wanted;
}

void peer_connection::note_divergence(protocol::storage_id const& sid, crypto::public_key_id const& origin, bool diverged) {
	std::unique_lock lock{mutex_};
	if(diverged) {
		diverged_.insert({sid, origin.data()});
	} else {
		diverged_.erase({sid, origin.data()});
	}
}

/// re-run the pulls the last announced heads call for (after a signer key arrived)
void peer_connection::resume_pulls() {
	std::map<protocol::storage_id, protocol::peer_heads> heads;
	{
		std::unique_lock lock{mutex_};
		heads = peer_heads_;
	}
	for(auto const& [sid, p] : heads) {
		if(sctx_.find_open_sync(sid)) {
			start_pulls(p);
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
	if(check_peer("request_key")) {
		auto key = sctx_.find_key(p.key);
		LOG_TRACE("request_key [key={}, held={}]", p.key, key.has_value());
		send_packet(protocol::response_key{p.cid, std::move(key)});
	}
}

void peer_connection::operator()(protocol::response_key const& p) {
	LOG_TRACE("response_key [held={}]", p.key.has_value());
	if(check_peer("response_key")) {
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
	if(check_peer("pull_records")) {
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
	if(check_peer("response_envelopes")) {
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
			// a condemned origin (the batch may have been the proof) is not followed further
			bool const more = progressed && !handle->condemned(p.origin) && p.origin_max.is_valid() && known < p.origin_max;
			if(more) {
				request_pull(p.sid, p.origin, known + 1, p.origin_max);
			} else if(progressed) {
				sctx_.note_caught_up(p.sid);
			}
		}
	}
}

void peer_connection::operator()(protocol::push_records const& p) {
	if(check_peer("push_records")) {
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
