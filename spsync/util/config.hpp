#pragma once

#include "json.hpp"

#include <securepath/database/connection.hpp>
#include <securepath/event_system/event_handler.hpp>

#include <mutex>
#include <vector>

namespace securepath::sync::util {
namespace events {
	struct on_config_changed {
		typedef void type(std::string);
	};
}

/**
 * Keeps configuration options and values
 * Options are referenced in form "parent.child.name.whatever" where left side of . is always parent containing the value
 * Changes are reported as events::on_config_changed (one per changed leaf) through the
 * event handler given at construction, after the write and outside the lock.
 */
class config {
public:
	/// Create config without database backend
	explicit config(event_system::event_handler* events = nullptr);

	/// Create config with database backend where the values are stored
	config(database::connection_ptr, std::string_view tablename, event_system::event_handler* events = nullptr);

	/// Sets the database and writes current values to it. If same values exists in db, they are overwritten
	void set_database(database::connection_ptr, std::string_view tablename);

	/** Sets value, allows to set/overwrite leaf values if only_leaf is true (throw if trying to overwrite branch)
	 *  Otherwise allow to overwrite whole branches of tree which can be dangerous if not used carefully
	 */
	void set(std::string_view option, json::value const&, bool only_leaf = true);

	/// Find option if it exists
	std::optional<json::value> find(std::string_view option) const;

	/// Get option if it exists but throw in case it does not
	json::value get(std::string_view option) const;

	/// Get option or the given default value if no option exists
	json::value get_default(std::string_view option, json::value const& def) const;

	/// remove value of config option
	void remove(std::string_view option);
protected:
	void create_table();
	void load();
	/// write the value (an object recursively as leaves), collecting the written keys
	void update_db(std::string_view key, json::value const& v, std::vector<std::string>& changed);
	void remove_db(std::string_view key, json::value const& v, std::vector<std::string>& changed);
	void set_impl(std::string_view key, json::value const& v, bool overwrite);
	void notify(std::vector<std::string> const& changed) const;
private:
	mutable std::mutex mutex_;
	event_system::event_handler* events_{};
	database::connection_ptr db_;
	std::string tablename_;
	json::object root_;
};

}
