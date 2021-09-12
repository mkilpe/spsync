#pragma once

#include "member.hpp"
#include "record_data.hpp"

#include <spsync/core/crypto_context.hpp>
#include <spsync/core/record_interface.hpp>
#include <spsync/comm/net_connection.hpp>

#include <securepath/common/key_value_cache.hpp>
#include <securepath/database/connection.hpp>
#include <securepath/event_system/event_loop.hpp>
#include <securepath/network/encryption/context.hpp>

#include <memory>

namespace securepath::sync {

/// Provides client specific handling, like storage members and decryption of the records
class client_sync : public key_value_cache {
public:

	client_sync(event_system::event_loop& loop, database::connection_ptr);
	~client_sync();

	void init(storage_id const& sid, network_connection& conn);

	/// this needs to be called from the most derived class when destroying it to make sure there are no calls via the virtual functions any more
	void stop_handler();

	record_handle send_data_change(object_id, metadata, record_data_handle = {});
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

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}
