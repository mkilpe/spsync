#include "net_data_channel.hpp"

#include <spsync/protocol/data_protocol.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/network/encryption/framing.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>

#include "pending_calls.hpp"

#include <asio/steady_timer.hpp>

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <variant>
#include <spsync/util/move_only_function.hpp>

namespace securepath::sync {
namespace {

/// a reply of the data server as it comes off the wire, whichever call it answers
using reply_packet = std::variant<protocol::upload_data_manifest_reply, protocol::upload_data_chunk_reply
	, protocol::download_data_open_reply, protocol::download_data_piece_reply>;

/// a call still out: answered with its reply, or with an error and whether it was the
/// transport that failed (the holder is down: try the next one) or the holder that refused
using pending_call = move_only_function<void(util::result<reply_packet>, bool transport_failure)>;

/// a link is to a server AND the key it has to authenticate with: a grant that names
/// another key for the same address does not get the link an earlier grant's key opened
std::string endpoint_name(data_endpoint const& e) {
	return e.host + ":" + std::to_string(e.port) + "/" + to_hex(e.key.data());
}

/**
 * The connection to one data server: calls answered by their reply packets, by call id.
 * A server that says nothing for the silence limit while calls are out is given up
 * (the calls fail as a transport failure: the next holder). Closed with close_later:
 * from anywhere, without waiting for the strand, which the one io thread of a small
 * client cannot do - the calls out fail when on_disconnected comes.
 */
class data_link : public network::encrypted_connection, public std::enable_shared_from_this<data_link> {
public:
	data_link(network::context& context, data_endpoint endpoint, std::chrono::seconds silence_limit)
	: encrypted_connection(context)
	, endpoint_(std::move(endpoint))
	, silence_limit_(silence_limit)
	, silence_(context.io_context())
	{}

	~data_link() {
		encrypted_connection::close();
	}

	void start(std::chrono::seconds timeout) {
		LOG_TRACE("connecting to data server {}", endpoint_name(endpoint_));
		{
			std::unique_lock lock{mutex_};
			last_received_ = std::chrono::steady_clock::now();
		}
		connect(endpoint_.host, endpoint_.port, timeout);
		watch();
	}

	bool dead() const {
		std::unique_lock lock{mutex_};
		return dead_;
	}

	/// the channel closes: what is out ends here - not "this holder is down, the next
	/// one" - when the strand gets to it
	void close_later() {
		{
			std::unique_lock lock{mutex_};
			closing_ = true;
			silence_.cancel();
		}
		encrypted_connection::close_later(make_error(securepath::errc::invalid_state, "data channel closed"), shared_from_this());
	}

private:
	/// look every half limit whether the server went silent
	void watch() {
		std::unique_lock lock{mutex_};
		silence_.expires_after(std::chrono::duration_cast<std::chrono::milliseconds>(silence_limit_) / 2);
		silence_.async_wait([weak = weak_from_this()](std::error_code const& ec) {
			auto self = weak.lock();
			if(self && !ec && self->check_silence()) {
				self->watch();
			}
		});
	}

	/// calls out and nothing received for the limit: the link is given up. True while it goes on
	bool check_silence() {
		bool silent{};
		bool dead{};
		{
			std::unique_lock lock{mutex_};
			dead = dead_;
			silent = !dead_ && !calls_.empty() && std::chrono::steady_clock::now() - last_received_ >= silence_limit_;
		}
		if(silent) {
			LOG_WARN("data server {} says nothing: given up with {} calls out", endpoint_name(endpoint_), calls_.size());
			encrypted_connection::close_later(make_error(securepath::errc::timeout, "the data server says nothing"), shared_from_this());
		}
		return !silent && !dead;
	}

public:

	/**
	 * Make a call: make(cid) is the packet, handler gets its Reply, or the error and
	 * whether it was the transport. The packet goes out at once, or when the hello is
	 * answered; on a dead link the handler is failed at once.
	 */
	template<typename Reply, typename Make>
	void call(Make make, move_only_function<void(util::result<Reply>, bool transport_failure)> handler) {
		auto const cid = ++call_id_;
		auto bytes = serialisation::asn_der_serialise_choice<protocol::c2d_types>(make(cid));
		post(cid, std::move(bytes), [handler = std::move(handler)](util::result<reply_packet> answer, bool transport_failure) mutable {
			if(!answer) {
				handler(util::result<Reply>{answer.get_error()}, transport_failure);
			} else if(auto const* reply = std::get_if<Reply>(&answer.value())) {
				handler(util::result<Reply>{*reply}, false);
			} else {
				handler(util::result<Reply>{make_error(securepath::errc::invalid_data, "a reply of another kind")}, false);
			}
		});
	}

private:
	void post(protocol::call_id cid, octet_vector bytes, pending_call answer) {
		std::unique_lock lock{mutex_};
		if(dead_) {
			auto const err = failure_;
			lock.unlock();
			answer(util::result<reply_packet>{err}, true);
		} else {
			calls_.add(cid, std::move(answer));
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
		heard();
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
		bool closing{};
		{
			std::unique_lock lock{mutex_};
			closing = closing_;
		}
		// the channel's own close is not "this holder is down": nobody tries the next one
		fail_all(err ? err : make_error(securepath::errc::invalid_state, "data connection closed"), !closing);
	}

	void heard() {
		std::unique_lock lock{mutex_};
		last_received_ = std::chrono::steady_clock::now();
	}

	void on_received(octet_span s) override {
		heard();
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

	/// every other packet is the reply to a call
	template<typename Reply>
	void handle(Reply const& p) {
		std::optional<pending_call> answer;
		{
			std::unique_lock lock{mutex_};
			answer = calls_.take(p.cid);
		}
		if(answer) {
			(*answer)(util::result<reply_packet>{reply_packet{p}}, false);
		}
	}

	/// the link is gone: every call still out gets the error, new ones too. An open that
	/// is out may go on at the next holder when the transport failed (RD13 failover)
	void fail_all(error const& err, bool transport_failure = true) {
		std::vector<pending_call> calls;
		{
			std::unique_lock lock{mutex_};
			if(!dead_) {
				dead_ = true;
				failure_ = err;
			}
			calls = calls_.take_all();
			outbox_.clear();
		}
		for(auto& answer : calls) {
			answer(util::result<reply_packet>{err}, transport_failure);
		}
	}

private:
	data_endpoint const endpoint_;
	std::chrono::seconds const silence_limit_;
	std::atomic<protocol::call_id> call_id_{0};
	// a manifest reply names up to max_data_chunks digests: the transport frame is the bound
	serialisation::packet_deserialiser<protocol::d2c_types> deser_{network::max_frame_size};

	mutable std::mutex mutex_;
	pending_calls<protocol::call_id, pending_call> calls_;
	/// packets waiting for the hello to be answered
	std::vector<octet_vector> outbox_;
	error failure_;
	std::chrono::steady_clock::time_point last_received_;
	asio::steady_timer silence_;
	bool ready_{};
	bool dead_{};
	/// the channel closed the link: what is out is over, not failed over
	bool closing_{};
};

/// what a holder said to a call: the error it refused with, none when it did not
template<typename Reply>
std::optional<error> refusal(util::result<Reply> const& answer) {
	std::optional<error> ret;
	if(!answer) {
		ret = answer.get_error();
	} else if(answer.value().error) {
		ret = protocol::to_error(answer.value().error);
	}
	return ret;
}

error channel_closed() {
	return make_error(securepath::errc::invalid_state, "data channel closed");
}

}

class net_data_channel::impl : public std::enable_shared_from_this<impl> {
public:
	impl(network::context& context, ticket_source tickets, std::chrono::seconds timeout, std::chrono::seconds silence_limit)
	: context_(context)
	, tickets_(std::move(tickets))
	, timeout_(timeout)
	, silence_limit_(silence_limit)
	{}

	void open_upload(data_descriptor const& descriptor, data_manifest const& manifest, open_callback cb) {
		open_transfer(upload_opening_, descriptor, manifest, std::move(cb));
	}

	void open_download(data_descriptor const& descriptor, download_callback cb) {
		open_transfer(download_opening_, descriptor, data_manifest{}, std::move(cb));
	}

	void send_piece(data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, octet_vector bytes, piece_callback cb) {
		auto const r = find_route(uploads_, id);
		if(!r) {
			cb(make_error(protocol::errc::no_such_upload, "no upload opened for the data"));
		} else {
			r->link->call<protocol::upload_data_chunk_reply>(
				[&](protocol::call_id cid) { return protocol::upload_data_chunk{cid, r->sid, id, chunk_no, offset, std::move(bytes)}; }
				, [cb = std::move(cb)](util::result<protocol::upload_data_chunk_reply> answer, bool) mutable { cb(refusal(answer)); });
		}
	}

	void fetch_piece(data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, std::uint32_t size, fetch_callback cb) {
		auto const r = find_route(downloads_, id);
		if(!r) {
			cb(util::result<octet_vector>{make_error(protocol::errc::data_not_held, "no download opened for the data")});
		} else {
			r->link->call<protocol::download_data_piece_reply>(
				[&](protocol::call_id cid) { return protocol::download_data_piece{cid, r->sid, id, chunk_no, offset, size}; }
				, [cb = std::move(cb)](util::result<protocol::download_data_piece_reply> answer, bool) mutable { cb(fetched(answer)); });
		}
	}

	void close() {
		std::map<std::string, std::shared_ptr<data_link>> links;
		{
			std::unique_lock lock{mutex_};
			links.swap(links_);
			uploads_.clear();
			downloads_.clear();
		}
		for(auto& [name, link] : links) {
			link->close_later();
		}
	}

private:
	/// where the pieces of an opened transfer go: the data server that opened it
	struct route {
		octet_vector sid;
		std::shared_ptr<data_link> link;
		std::chrono::steady_clock::time_point last_used;
	};
	using routes = std::map<data_id, route>;

	/// routes nothing moved on for this long go, and the least recently used one when
	/// this many are kept: a transfer that ended is not told to the channel
	static constexpr std::chrono::minutes route_idle_limit{10};
	static constexpr std::size_t max_routes{256};

	/// one attempt to open a transfer: the grant and how far down its holder list we are
	template<typename Result>
	struct attempt {
		attempt(asio::io_context& io, data_descriptor d, data_manifest m, move_only_function<void(util::result<Result>)> cb)
		: descriptor(std::move(d))
		, manifest(std::move(m))
		, callback(std::move(cb))
		, wait(io)
		{}

		/// the ticket is answered once: by the record server, or by the wait for it
		/// running out. True for the caller that gets to answer
		bool first_answer() {
			std::unique_lock lock{mutex};
			bool const first = !answered;
			answered = true;
			if(first) {
				wait.cancel();
			}
			return first;
		}

	public:
		data_descriptor descriptor;
		/// what an upload opens with; a download opens with the ticket alone
		data_manifest manifest;
		data_grant grant;
		move_only_function<void(util::result<Result>)> callback;
		std::size_t holder{};
		std::mutex mutex;
		asio::steady_timer wait;
		bool answered{};
	};

	/// what the opening of an upload and of a download differ in
	template<typename Result>
	struct opening {
		data_right right;
		/// the answer when the grant names no holder
		error nobody;
		/// a refusal that moves the opening on to the next holder (RD13)
		bool (*moves_on)(error const&);
		/// where the pieces go once a holder took the opening
		routes impl::* routes_of;
		/// the call that opens at a holder
		void (*open)(data_link&, attempt<Result> const&, move_only_function<void(util::result<Result>, bool)>);
	};

	/**
	 * Open a transfer with a fresh grant at the first holder that can be reached: a holder
	 * that is down is the next entry, so is one whose refusal moves the opening on; any
	 * other refusal is the answer.
	 */
	template<typename Result>
	void open_transfer(opening<Result> const& how, data_descriptor const& descriptor, data_manifest const& manifest
		, move_only_function<void(util::result<Result>)> cb) {
		auto att = std::make_shared<attempt<Result>>(context_.io_context(), descriptor, manifest, std::move(cb));
		std::weak_ptr<impl> weak = shared_from_this();
		// the record server has the silence limit to answer the ticket request
		att->wait.expires_after(silence_limit_);
		att->wait.async_wait([att](std::error_code const& ec) {
			if(!ec && att->first_answer()) {
				att->callback(util::result<Result>{make_error(securepath::errc::timeout, "no answer to the ticket request")});
			}
		});
		tickets_(descriptor, how.right, [weak, att, &how](util::result<data_grant> grant) {
			auto self = weak.lock();
			if(!att->first_answer()) {
				LOG_INFO("a ticket came after the wait for it ran out, dropped");
			} else if(!self) {
				att->callback(util::result<Result>{channel_closed()});
			} else if(!grant) {
				att->callback(util::result<Result>{grant.get_error()});
			} else {
				att->grant = std::move(grant.value());
				self->try_holder(how, att, how.nobody);
			}
		});
	}

	/// open at the attempt's current holder; last_error is the answer when none is left
	template<typename Result>
	void try_holder(opening<Result> const& how, std::shared_ptr<attempt<Result>> const& att, error const& last_error) {
		if(att->holder >= att->grant.holders.size()) {
			att->callback(util::result<Result>{last_error});
		} else {
			auto link = acquire_link(att->grant.holders[att->holder]);
			std::weak_ptr<impl> weak = shared_from_this();
			how.open(*link, *att, [weak, &how, att, link](util::result<Result> answer, bool transport_failure) {
				auto self = weak.lock();
				if(answer && self) {
					self->remember(how, att->grant.ticket, link);
					att->callback(std::move(answer));
				} else if((transport_failure || how.moves_on(answer.get_error())) && self) {
					++att->holder;
					self->try_holder(how, att, answer.get_error());
				} else {
					att->callback(util::result<Result>{answer ? channel_closed() : answer.get_error()});
				}
			});
		}
	}

	template<typename Result>
	void remember(opening<Result> const& how, data_ticket const& ticket, std::shared_ptr<data_link> link) {
		std::unique_lock lock{mutex_};
		auto& of = this->*how.routes_of;
		trim_routes(of);
		of[ticket.data()] = route{ticket.storage_id(), std::move(link), std::chrono::steady_clock::now()};
	}

	/// requires the mutex: the idle routes go, and the least recently used when full
	static void trim_routes(routes& of) {
		auto const now = std::chrono::steady_clock::now();
		std::erase_if(of, [&](auto const& r) { return now - r.second.last_used > route_idle_limit; });
		if(of.size() >= max_routes) {
			of.erase(std::ranges::min_element(of, {}, [](auto const& r) { return r.second.last_used; }));
		}
	}

	std::optional<route> find_route(routes& of, data_id const& id) {
		std::unique_lock lock{mutex_};
		std::optional<route> ret;
		auto it = of.find(id);
		if(it != of.end()) {
			it->second.last_used = std::chrono::steady_clock::now();
			ret = it->second;
		}
		return ret;
	}

	/// the live connection to the data server, a new one when there is none
	std::shared_ptr<data_link> acquire_link(data_endpoint const& endpoint) {
		std::shared_ptr<data_link> link;
		bool is_new = false;
		{
			std::unique_lock lock{mutex_};
			auto& slot = links_[endpoint_name(endpoint)];
			is_new = !slot || slot->dead();
			if(is_new) {
				slot = std::make_shared<data_link>(context_, endpoint, silence_limit_);
			}
			link = slot;
		}
		if(is_new) {
			link->start(timeout_);
		}
		return link;
	}

	// -- the two openings --

	/// the data server has no room for the data: another one may (it behaves as if it
	/// was not on the ring for new data)
	static bool is_full(error const& err) {
		return err.code() == make_error_code(protocol::errc::data_quota_exceeded)
			|| err.code() == make_error_code(protocol::errc::data_too_big);
	}

	/// the data server does not hold the data: another one may
	static bool is_not_held(error const& err) {
		return err.code() == make_error_code(protocol::errc::data_not_held);
	}

	/// the manifest to a holder: its answer is the chunks it has
	static void open_upload_at(data_link& link, attempt<have_bitmap> const& att
		, move_only_function<void(util::result<have_bitmap>, bool)> answer) {
		link.call<protocol::upload_data_manifest_reply>(
			[&](protocol::call_id cid) { return protocol::upload_data_manifest{cid, att.grant.ticket, att.manifest}; }
			, [answer = std::move(answer), chunks = att.descriptor.chunk_count()](util::result<protocol::upload_data_manifest_reply> reply, bool transport) mutable {
				auto const refused = refusal(reply);
				answer(refused ? util::result<have_bitmap>{*refused} : util::result<have_bitmap>{have_bitmap{chunks, reply.value().have}}, transport);
			});
	}

	/// the opening of a download: the holder's manifest and what it has
	static void open_download_at(data_link& link, attempt<download_info> const& att
		, move_only_function<void(util::result<download_info>, bool)> answer) {
		link.call<protocol::download_data_open_reply>(
			[&](protocol::call_id cid) { return protocol::download_data_open{cid, att.grant.ticket}; }
			, [answer = std::move(answer), chunks = att.descriptor.chunk_count()](util::result<protocol::download_data_open_reply> reply, bool transport) mutable {
				auto const refused = refusal(reply);
				answer(refused ? util::result<download_info>{*refused}
					: util::result<download_info>{download_info{std::move(reply.value().manifest), have_bitmap{chunks, std::move(reply.value().have)}}}, transport);
			});
	}

	/// the answer to a fetched piece; a transfer quota window says when the next one opens
	static util::result<octet_vector> fetched(util::result<protocol::download_data_piece_reply>& reply) {
		util::result<octet_vector> ret;
		auto const refused = refusal(reply);
		if(refused && reply && reply.value().retry_after != 0) {
			ret = protocol::make_retry_error(protocol::errc::data_transfer_quota_exceeded, reply.value().retry_after);
		} else if(refused) {
			ret = *refused;
		} else {
			ret = std::move(reply.value().bytes);
		}
		return ret;
	}

private:
	network::context& context_;
	ticket_source const tickets_;
	std::chrono::seconds const timeout_;
	std::chrono::seconds const silence_limit_;

	opening<have_bitmap> const upload_opening_{data_right::upload
		, make_error(securepath::errc::no_such_data, "the grant names no data server"), &is_full, &impl::uploads_, &open_upload_at};
	opening<download_info> const download_opening_{data_right::download
		, make_error(protocol::errc::data_not_held, "the grant names no data server"), &is_not_held, &impl::downloads_, &open_download_at};

	std::mutex mutex_;
	/// one connection per data server and key
	std::map<std::string, std::shared_ptr<data_link>> links_;
	/// where the chunks of an opened upload go
	routes uploads_;
	/// where the pieces of an opened download come from
	routes downloads_;
};

net_data_channel::net_data_channel(network::context& context, ticket_source tickets, std::chrono::seconds timeout
	, std::chrono::seconds silence_limit)
: impl_(std::make_shared<impl>(context, std::move(tickets), timeout, silence_limit))
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

void net_data_channel::open_download(data_descriptor const& descriptor, download_callback cb) {
	impl_->open_download(descriptor, std::move(cb));
}

void net_data_channel::fetch_piece(data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, std::uint32_t size, fetch_callback cb) {
	impl_->fetch_piece(id, chunk_no, offset, size, std::move(cb));
}

void net_data_channel::close() {
	impl_->close();
}

}
