#pragma once

#include "json.hpp"

#include <securepath/database/connection.hpp>
#include <securepath/event_system/broadcast_event_handler.hpp>

namespace securepath::sync::util {
namespace events {
	struct on_config_changed {
		typedef void type(std::string);
	};
}

/**
 * Keeps configuration options and values
 * Options are referenced in form "parent.child.name.whatever" where left side of . is always parent containing the value
 */
class config {
public:
	config(database::connection_ptr, std::string_view tablename = {});

	/** Sets value, allows to set/overwrite leaf values if only_leaf is true (throw if trying to overwrite branch)
	 *  Otherwise allow to overwrite whole branches of tree which can be dangerous if not used carefully
	 */
	void set(std::string_view option, json::value const&, bool only_leaf = true);

	/// Find option if it exists
	std::optional<json::value> find(std::string_view option) const;

	/// Find option if it exists but throw in case it does not
	json::value get(std::string_view option) const;

	/// Get broadcast event handler to listen changes
	event_system::broadcast_event_handler& change_notification();
private:
	mutable std::mutex mutex_;
	event_system::broadcast_event_handler events_;
	database::connection_ptr db_;
	json::object root_;
};

}
