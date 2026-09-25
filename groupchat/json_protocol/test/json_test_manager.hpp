
#pragma once

#include "json_test_helpers.hpp"
#include <spsync/util/print.hpp>

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
		[&](auto type, auto e){ event_handler(type, e); },
		remove_db_helper(print("client_%", id), action))
	{
	}

	void event_handler(event_type type, std::string event) {
		std::unique_lock l{mutex};
		events.push_back(std::make_pair(type, event));
	}

	void clear_events() {
		std::unique_lock l{mutex};
		events.clear();
	}

	std::size_t events_size() const {
		std::unique_lock l{mutex};
		return events.size();
	}

	bool contains_event(event_type type, std::string exp) const {
		std::unique_lock l{mutex};
		for(auto&& v : events) {
			if(v.first == type && check_contains_json(v.second, exp))
				return true;
		}
		return false;
	}

	bool has_connect_event() const {
		return contains_event(event_type::state_change, R"(
				{"type": "connection",
				 "data":
				 	{ "connection": "online" }
				 })");
	}

	bool has_disconnect_event() const {
		return contains_event(event_type::state_change, R"(
				{"type": "connection",
				 "data":
				 	{ "connection": "offline" }
				 })");
	}

	bool has_create_event(std::string cid) const {
		return contains_event(event_type::state_change, print(R"(
				{"type": "chat",
				 "data":
				 	{ "action": "create",
				 	  "chat": "%" }
				 })", cid));
	}

	bool has_failed_create_event(std::string cid) const {
		return contains_event(event_type::state_change, print(R"(
				{"type": "chat",
				 "data":
				 	{ "action": "create",
				 	  "chat": "%",
				 	  "error": {} }
				 })", cid));
	}

	bool has_join_event(std::string cid) const {
		return contains_event(event_type::state_change, print(R"(
				{"type": "chat",
				 "data":
				 	{ "action": "join",
				 	  "chat": "%" }
				 })", cid));
	}

	bool has_message_event(std::string cid, std::string mid) const {
		return contains_event(event_type::state_change, print(R"(
				{"type": "chat",
				 "data":
				 	{ "action": "message",
				 	  "chat": "%",
				 	  "message": {"id" : "%"} }
				 })", cid, mid));
	}

	bool has_file_event(std::string cid, std::string fid) const {
		return contains_event(event_type::state_change, print(R"(
				{"type": "chat",
				 "data":
				 	{ "action": "file",
				 	  "chat": "%",
				 	  "file": {"file" : "%"} }
				 })", cid, fid));
	}

	bool has_file_state_event(std::string cid, std::string fid, std::string state) const {
		return contains_event(event_type::state_change, print(R"(
				{"type": "chat",
				 "data":
				 	{ "action": "file_state",
				 	  "chat": "%",
				 	  "file": "%",
				 	  "state": "%" }
				 })", cid, fid, state));
	}

	bool has_contacting_event(crypto::public_key_id kid, std::string name, std::string message) const {
		return contains_event(event_type::request, print(R"(
				{"type": "contact",
				 "data":
				 	{ "action": "contacting",
				 	  "sender": {"id": "%", "name": "%"},
				 	  "message": "%" }
				 })", kid.in_hex(), name, message));
	}

	bool has_contacting_event(std::string state, crypto::public_key_id kid, std::string name, std::string message) const {
		return contains_event(event_type::request, print(R"(
				{"type": "contact",
				 "data":
				 	{ "action": "contacting",
				 	  "state": "%",
				 	  "sender": {"id": "%", "name": "%"},
				 	  "message": "%" }
				 })", state, kid.in_hex(), name, message));
	}

	bool has_invitation_event(crypto::public_key_id kid, std::string name, std::string message) const {
		return contains_event(event_type::request, print(R"(
				{"type": "invite",
				 "data":
				 	{ "action": "invitation",
				 	  "sender": {"id": "%", "name": "%"},
				 	  "message": "%" }
				 })", kid.in_hex(), name, message));
	}

	mutable std::mutex mutex;
	std::deque<std::pair<event_type, std::string>> events;
};

}