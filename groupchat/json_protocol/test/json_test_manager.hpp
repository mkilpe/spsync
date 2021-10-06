
#pragma once

#include "json_test_helpers.hpp"

#include <groupchat/json_protocol/json_helpers.hpp>
#include <groupchat/json_protocol/json_manager.hpp>
#include <groupchat/core/groupchat.hpp>
#include <spsync/test/test_context.hpp>
#include <securepath/util/print_util.hpp>

namespace securepath::groupchat::json_protocol::test {

enum db_action {
	keep_db,
	remove_db
};

inline std::string remove_db_helper(std::string db, db_action action) {
	if(action == remove_db) {
		std::remove(groupchat_config{db}.db().c_str());
	}
	return db;
}

struct json_test_manager : json_manager {
	json_test_manager(sync::test::test_context& net_context, int id, db_action action)
	: json_manager(
		net_context.client_context(id),
		[&](auto e){ event_handler(e); },
		remove_db_helper(print("client_%", id), action))
	{
	}

	void event_handler(std::string event) {
		std::unique_lock l{mutex};
		events.push_back(event);
	}

	void clear_events() {
		std::unique_lock l{mutex};
		events.clear();
	}

	bool contains_event(std::string exp) const {
		std::unique_lock l{mutex};
		for(auto&& v : events) {
			if(check_contains_json(v, exp))
				return true;
		}
		return false;
	}

	bool has_connect_event() const {
		return contains_event(R"(
				{"type": "connection state changed",
				 "data":
				 	{ "connection": "online" }
				 })");
	}

	bool has_disconnect_event() const {
		return contains_event(R"(
				{"type": "connection state changed",
				 "data":
				 	{ "connection": "offline" }
				 })");
	}

	bool has_create_event(std::string cid) const {
		return contains_event(print(R"(
				{"type": "chat state changed",
				 "data":
				 	{ "action": "create",
				 	  "chat": "%" }
				 })", cid));
	}

	bool has_failed_create_event(std::string cid) const {
		return contains_event(print(R"(
				{"type": "chat state changed",
				 "data":
				 	{ "action": "create",
				 	  "chat": "%",
				 	  "error": {} }
				 })", cid));
	}

	bool has_join_event(std::string cid) const {
		return contains_event(print(R"(
				{"type": "chat state changed",
				 "data":
				 	{ "action": "join",
				 	  "chat": "%" }
				 })", cid));
	}

	bool has_message_event(std::string cid, std::string mid) const {
		return contains_event(print(R"(
				{"type": "chat state changed",
				 "data":
				 	{ "action": "message",
				 	  "chat": "%",
				 	  "message": {"id" : "%"} }
				 })", cid, mid));
	}

	mutable std::mutex mutex;
	std::deque<std::string> events;
};

}