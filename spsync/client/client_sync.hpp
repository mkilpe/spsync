// SPDX-License-Identifier: MIT

#pragma once

#include "member.hpp"
#include "record_data.hpp"

#include <spsync/core/crypto_context.hpp>
#include <spsync/core/record_interface.hpp>
#include <spsync/comm/net_connection.hpp>
#include <spsync/engine/sync_engine_config.hpp>

#include <securepath/common/key_value_cache.hpp>
#include <securepath/database/connection.hpp>
#include <securepath/event_system/event_loop.hpp>
#include <securepath/network/encryption/context.hpp>

#include <memory>

namespace securepath::sync {

/// Provides client specific handling, like storage members and decryption of the records
class client_sync : public key_value_cache {
public:

	client_sync(network::context&, event_system::event_loop& loop, database::connection_ptr, sync_engine_config = {});
	~client_sync();

	void init(storage_id const& sid, network_connection& conn);

	/**
	 * The block the chain must start with (plan 5.5): the invitation's first block for a
	 * joiner, the segment a prune left. Set before init() for a session; kept by the
	 * caller for the next ones (sync_engine_config::trusted_anchor).
	 */
	void set_trusted_anchor(chain_block_id const&);

	/// this needs to be called from the most derived class when destroying it to make sure there are no calls via the virtual functions any more
	void stop_handler();

	/// the data handle is a source streamed into the data store (engine_input::sync_object_change);
	/// it needs sync_engine_config::data_root
	record_handle send_data_change(object_id, metadata, record_data_handle = {});

	/// the record data of a change of a data change record (engine_input::object_data)
	record_data_handle object_data(record_handle, std::size_t change = 0);

	/// the same, fetched from the data servers when it is not held (engine_input::fetch_object_data)
	record_data_handle fetch_object_data(record_handle, std::size_t change = 0);
	record_handle send_user_change(users user_change, metadata = {});

	std::deque<std::unique_ptr<member>> members() const;

	/// find a member based on user_id
	std::unique_ptr<member> find_member(util::user_id const&) const;

	/// add new member, locally add pending member and make user change record
	std::unique_ptr<member> add_member(util::user_id const&);

	/// remove existing member, locally add pending remove and make user change record
	void remove_member(util::user_id const&);

	/// apply the users to current members
	void apply(users const&);

	sync::crypto_context& crypto_context() const;

protected:

	virtual void on_data_change(record_handle, std::deque<single_data_change>) = 0;
	virtual void on_user_change(record_handle, user_change) = 0;
	/// the server rejected a pending record for good (engine_output::on_record_rejected)
	virtual void on_record_rejected(record_handle, error) {}
	/// the local state of a record data changed (engine_output::on_data_state_changed)
	virtual void on_data_state_changed(data_id, record_data_state) {}
	/// a record data transfer ended with an error (engine_output::on_data_transfer_failed)
	virtual void on_data_transfer_failed(data_id, error) {}
	/// the server showed another history than the trusted anchor names (engine_output::on_anchor_mismatch)
	virtual void on_anchor_mismatch(chain_block) {}

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}
