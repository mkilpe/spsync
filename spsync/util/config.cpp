#include "config.hpp"

namespace securepath::sync::util {

config::config(database::connection_ptr db, std::string_view tablename)
: db_(db)
{
}

void config::set(std::string_view option, json::value const&, bool only_leaf) {

}

std::optional<json::value> config::find(std::string_view option) const {
	return std::nullopt;
}

json::value config::get(std::string_view option) const {
	return json::value{};
}

event_system::broadcast_event_handler& config::change_notification() {
	return events_;
}

}
