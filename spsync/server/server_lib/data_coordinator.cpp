#include "data_coordinator.hpp"

#include "data_release.hpp"
#include "data_replication_plan.hpp"
#include "data_server.hpp"
#include "peer_connection.hpp"
#include "storage.hpp"

#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <algorithm>
#include <map>

namespace securepath::sync {

/**
 * The storages a pass over many data looks at, each opened once for the time of the
 * pass when nobody has it open (a sweep asks about thousands of data of a storage:
 * opened per question it would be built and torn down as often) and given back at
 * the end, also when the pass is left by an exception.
 */
class data_coordinator::storage_pass {
public:
	explicit storage_pass(storage_server_context& records) : records_(records) {}
	storage_pass(storage_pass const&) = delete;
	storage_pass& operator=(storage_pass const&) = delete;

	~storage_pass() {
		for(auto& [sid, handle] : opened_) {
			if(handle) {
				records_.release_sync(std::move(handle));
			}
		}
	}

	/// the storage when it exists here, null otherwise
	std::shared_ptr<storage> get(protocol::storage_id const& sid) {
		auto it = opened_.find(sid);
		if(it == opened_.end()) {
			it = opened_.emplace(sid, open(sid)).first;
		}
		return it->second;
	}

private:
	std::shared_ptr<storage> open(protocol::storage_id const& sid) const {
		std::shared_ptr<storage> handle;
		try {
			handle = records_.find_sync(sid);
		} catch(std::exception const& ex) {
			LOG_WARN("cannot look at storage {}: {}", to_hex(sid), ex.what());
		}
		return handle;
	}

private:
	storage_server_context& records_;
	std::map<protocol::storage_id, std::shared_ptr<storage>> opened_;
};

data_coordinator::data_coordinator(storage_server_context& records, crypto::private_data_access& keys, peer_source peers, params p)
: records_(records)
, keys_(keys)
, peers_(std::move(peers))
, params_(std::move(p))
, issuer_(params_.data_servers, availability_, params_.ticket_validity)
{}

util::result<issued_ticket> data_coordinator::issue_data_ticket(storage const& st, data_id const& id,
	crypto::public_key_id const& member, std::uint32_t right) {
	return issuer_.issue(st.id(), st.committed_data(id), member, right, keys_.my_private_key(), clock_type::now());
}

std::vector<data_endpoint> data_coordinator::data_endpoints() const {
	return issuer_.data_servers();
}

void data_coordinator::data_announced(protocol::announce_data const& p) {
	LOG_TRACE("data announcement of holder {} [{} entries]", p.holder, p.entries.size());
	availability_.set_load(p.holder, holder_load{p.stored_bytes, p.uploads_in_progress});
	if(p.view_begin) {
		availability_.forget_holder(p.holder);
	}
	std::vector<std::pair<protocol::storage_id, data_id>> complete;
	for(auto const& e : p.entries) {
		bool const news = availability_.announce(e.sid, e.data_id, data_holding{p.holder, e.have_chunks, e.total_chunks, e.complete});
		auto const handle = news ? records_.find_open_sync(e.sid) : nullptr;
		if(handle) {
			// RD4: clients waiting for the data fetch without polling
			handle->notify_data(e.data_id, true);
		}
		if(e.complete) {
			complete.emplace_back(e.sid, e.data_id);
		}
	}
	// RD13 copy count: a complete copy is where the other primary holders get theirs,
	// and after a whole view it is known what that holder lacks
	look_after_copies(p.view_end ? availability_.known_data() : complete);
}

bool data_coordinator::is_data_server(crypto::public_key_id const& key) const {
	auto const& servers = issuer_.data_servers();
	return key != server_id() && std::ranges::find(servers, key, &data_endpoint::key) != servers.end();
}

util::result<issued_ticket> data_coordinator::issue_replica_ticket(protocol::storage_id const& sid, data_id const& id,
	crypto::public_key_id const& data_server) {
	util::result<data_descriptor> committed{make_error(protocol::errc::no_such_storage)};
	storage_pass pass{records_};
	if(auto const st = pass.get(sid)) {
		committed = st->committed_data(id);
	}
	return issuer_.issue_replica(sid, committed, data_server, keys_.my_private_key(), clock_type::now());
}

std::vector<protocol::announce_data> data_coordinator::own_data_announcements() {
	std::vector<protocol::announce_data> ret;
	if(data_role_ && server_id().is_valid()) {
		ret = data_role_->announcements(server_id());
	}
	return ret;
}

void data_coordinator::attach_data_role(data_server& role, std::weak_ptr<void> owner) {
	data_role_ = &role;
	role.set_complete_handler([this, owner](protocol::storage_id const& sid, data_id const& id) {
		if(auto const keep = owner.lock()) {
			on_data_complete(sid, id);
		}
	});
	// the pulls this record role asks its own data role to make get their tickets here
	role.set_replica_ticket_source([this, owner](protocol::storage_id const& sid, data_descriptor const& descriptor
		, std::move_only_function<void(util::result<data_grant>)> answer) {
		auto const keep = owner.lock();
		auto issued = keep ? issue_replica_ticket(sid, descriptor.manifest_digest, server_id())
			: util::result<issued_ticket>{make_error(securepath::errc::invalid_state, "the record role is gone")};
		if(issued) {
			answer(data_grant{std::move(issued.value().ticket), std::move(issued.value().holders)});
		} else {
			answer(issued.get_error());
		}
	});
}

void data_coordinator::announce_own_data() {
	for(auto const& announcement : own_data_announcements()) {
		data_announced(announcement);
	}
}

bool data_coordinator::has_separate_data_servers() const {
	return std::ranges::any_of(issuer_.data_servers(), [this](data_endpoint const& e) { return e.key != server_id(); });
}

void data_coordinator::sweep_copies() {
	look_after_copies(availability_.known_data());
}

void data_coordinator::release_data(protocol::storage_id const& sid, std::vector<data_id> const& ids) {
	for(auto const& id : ids) {
		availability_.forget(sid, id);
	}
	if(data_role_) {
		data_role_->release(sid, ids);
	}
	auto const connections = peers_();
	for(auto const& packet : release_packets(sid, ids)) {
		for(auto const& conn : connections) {
			conn->release(packet);
		}
	}
}

data_availability const& data_coordinator::availability() const {
	return availability_;
}

data_standing data_coordinator::standing_of(storage_pass& pass, protocol::storage_id const& sid, data_id const& id) {
	data_standing ret;
	if(auto const st = pass.get(sid)) {
		auto const committed = st->committed_data(id);
		if(committed) {
			ret.descriptor = committed.value();
		} else {
			auto const code = committed.get_error().code();
			// unknown here may be a record that has not arrived yet when other record
			// servers have the storage as well
			ret.dead = code == make_error_code(protocol::errc::data_pruned)
				|| (code == make_error_code(protocol::errc::unknown_data) && st->modes().replication == replication_mode::none);
		}
	}
	return ret;
}

/// only written during the record role's start, stable afterwards
crypto::public_key_id const& data_coordinator::server_id() const {
	return records_.identity().server_id;
}

std::shared_ptr<peer_connection> data_coordinator::data_server_link(crypto::public_key_id const& key) {
	std::shared_ptr<peer_connection> ret;
	for(auto const& conn : peers_()) {
		if(!ret && conn->is_data_server_link() && conn->peer_id() == key) {
			ret = conn;
		}
	}
	return ret;
}

/**
 * The primary holders of these data that lack a copy are told to get one - the own
 * data role directly, a separate data server over its link; the data role of another
 * all-in-one replica is looked after by its own record role, which hears of the same
 * copies - and data that are held though the storage let them go are released.
 */
void data_coordinator::look_after_copies(std::vector<std::pair<protocol::storage_id, data_id>> const& data) {
	if(data.empty() || issuer_.data_servers().empty()) {
		return;
	}
	replication_plan plan;
	{
		storage_pass pass{records_};
		replication_view const view{issuer_.data_servers(), availability_, params_.data_copies
			, [this](crypto::public_key_id const& key) {
				return (key == server_id() && data_role_ != nullptr) || data_server_link(key) != nullptr;
			}
			, [&pass](protocol::storage_id const& sid, data_id const& id) { return standing_of(pass, sid, id); }};
		plan = plan_replication(view, data);
	}
	for(auto const& [target, storages] : plan.copies) {
		for(auto const& [sid, descriptors] : storages) {
			tell_to_replicate(target, sid, descriptors);
		}
	}
	for(auto const& [sid, ids] : plan.stale) {
		LOG_INFO("{} record data held by data servers though the storage let them go: released (sid={})", ids.size(), to_hex(sid));
		release_data(sid, ids);
	}
}

void data_coordinator::tell_to_replicate(crypto::public_key_id const& target, protocol::storage_id const& sid, std::vector<data_descriptor> const& descriptors) {
	LOG_INFO("data server {} is to hold copies of {} record data (sid={})", target, descriptors.size(), to_hex(sid));
	if(target == server_id() && data_role_) {
		data_role_->replicate(sid, descriptors);
	} else if(auto const link = data_server_link(target)) {
		for(auto const& packet : replicate_packets(sid, descriptors)) {
			link->replicate(packet);
		}
	}
}

/// the own data role completed a data: into the table here, and to the peers (RD13)
void data_coordinator::on_data_complete(protocol::storage_id const& sid, data_id const& id) {
	auto const announcement = server_id().is_valid() ? data_role_->announcement(server_id(), sid, id) : std::nullopt;
	if(announcement) {
		data_announced(*announcement);
		for(auto const& conn : peers_()) {
			conn->announce(*announcement);
		}
	}
}

}
