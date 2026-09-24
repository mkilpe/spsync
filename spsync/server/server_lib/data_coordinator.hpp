#pragma once

#include "data_availability.hpp"
#include "storage_data_context.hpp"
#include "storage_server_context.hpp"
#include "ticket_issuer.hpp"

#include <securepath/crypto/private_data_access.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <vector>

using namespace std::chrono_literals;

namespace securepath::sync {

class data_server;
struct data_standing;
class peer_connection;

/**
 * The record role's side of the record data (record_data.txt RD12/RD13): the tickets it
 * issues, the availability table the data servers' announcements feed, the copies it
 * looks after (RDS 10) and the releases it sends (RDS 9) - with the own data role when
 * this server has one (all-in-one) and the links to the separate data servers. It sees
 * the storages through the record role's context and the peers through the connections
 * the record role keeps; storage_server owns one and drives its sweep.
 */
class data_coordinator : public storage_data_context {
public:
	struct params {
		/// the data-role servers of the storages of this server, see storage_server_params
		std::vector<data_endpoint> data_servers;
		std::chrono::seconds ticket_validity{600s};
		/// copy count k (RD13)
		std::uint32_t data_copies{2};
	};

	/// every live peer connection of the record role, outgoing and accepted
	using peer_source = std::function<std::vector<std::shared_ptr<peer_connection>>()>;

	data_coordinator(storage_server_context& records, crypto::private_data_access& keys, peer_source, params);

	// -- storage_data_context, see storage_data_context.hpp --
	util::result<issued_ticket> issue_data_ticket(storage const&, data_id const&,
		crypto::public_key_id const& member, std::uint32_t right) override;
	std::vector<data_endpoint> data_endpoints() const override;
	void data_announced(protocol::announce_data const&) override;
	bool is_data_server(crypto::public_key_id const&) const override;
	util::result<issued_ticket> issue_replica_ticket(protocol::storage_id const&, data_id const&,
		crypto::public_key_id const& data_server) override;
	std::vector<protocol::announce_data> own_data_announcements() override;

	/**
	 * This server has the data role too (all-in-one): what its data server completes
	 * goes into the table here and is announced to the peers, and the pulls this record
	 * role asks it to make get their tickets here. The role's handlers run on its
	 * threads and may outlive the record role: owner keeps it alive while one runs.
	 */
	void attach_data_role(data_server&, std::weak_ptr<void> owner);

	/// what the own data role held before this start goes into the table as well
	void announce_own_data();

	/// a data server other than this server is configured: it will dial the s2s listener
	bool has_separate_data_servers() const;

	/// every known data checked for missing copies: what an announcement or a data server
	/// link coming up did not already trigger, and pulls that ended early
	void sweep_copies();

	/**
	 * No record of the storage names these data any more (RD9): nobody is sent to a
	 * holder for them again, the own data role drops them and the separate data servers
	 * are told over their links. A data server that is not connected now keeps its
	 * chunks: the release is not repeated (see record_data.txt RDS 9).
	 */
	void release_data(protocol::storage_id const&, std::vector<data_id> const&);

	/// the availability table the ticket answers are ordered from (tests and tooling)
	data_availability const& availability() const;

private:
	class storage_pass;

	static data_standing standing_of(storage_pass&, protocol::storage_id const&, data_id const&);
	crypto::public_key_id const& server_id() const;
	std::shared_ptr<peer_connection> data_server_link(crypto::public_key_id const&);
	void look_after_copies(std::vector<std::pair<protocol::storage_id, data_id>> const& data);
	void tell_to_replicate(crypto::public_key_id const& target, protocol::storage_id const&, std::vector<data_descriptor> const&);
	void on_data_complete(protocol::storage_id const&, data_id const&);

private:
	storage_server_context& records_;
	crypto::private_data_access& keys_;
	peer_source peers_;
	params params_;
	data_availability availability_;
	ticket_issuer issuer_;
	/// the data role of this server when it has one (all-in-one)
	data_server* data_role_{};
};

}
