// SPDX-License-Identifier: MIT

#include "cli_groupchat.hpp"
#include <spsync/util/print.hpp>

#include <groupchat/core/events.hpp>
#include <spsync/client/events.hpp>

#include <securepath/util/string_util.hpp>
#include <securepath/util/print_util.hpp>

#include <format>

namespace securepath::groupchat {

cli_groupchat::cli_groupchat(event_system::event_loop& loop, cli_window& win, gc_cli_config config)
: event_handler(loop)
, groupchat(*this, groupchat_config{.path=config.path, .root_public_key_file=config.root})
, win_(win)
, config_(config)
{
}

cli_groupchat::~cli_groupchat() {
	stop_handler();
}

std::optional<int> cli_groupchat::map_to_channel(chat_id const& cid) const {
	auto it = channel_map_.find(cid);
	return it != channel_map_.end() ? it->second : std::optional<int>{};
}

std::optional<chat_id> cli_groupchat::map_to_cid(int c) const {
	auto it = cid_map_.find(c);
	return it != cid_map_.end() ? it->second : std::optional<chat_id>{};
}

int cli_groupchat::add_channel(chat_id const& cid, std::string const& name) {
	int i = 0;
	auto it = channel_map_.find(cid);
	if(it != channel_map_.end()) {
		i = it->second;
	} else {
		// the window owns the channel numbering; the chat maps onto its channel
		i = win_.add_channel(to_wstring(name));
		channel_map_[cid] = i;
		cid_map_[i] = cid;
	}
	return i;
}

void cli_groupchat::remove_channel(int c) {
	auto it = cid_map_.find(c);
	if(it != cid_map_.end()) {
		channel_map_.erase(it->second);
		cid_map_.erase(it);
	}
}

void cli_groupchat::on_connect() {
	win_.add_info(0, L"connected to packet server");
}

void cli_groupchat::on_disconnect(error err) {
	auto s = print("disconnected from packet server (error=%)", err);
	win_.add_info(0, to_wstring(s));
}

void cli_groupchat::on_server_connect(server_id sid) {
	auto conn = find(sid);
	auto s = print("connected to sync server % (%)", sid, conn ? std::format("{}", conn->current_endpoint()) : "?");
	win_.add_info(0, to_wstring(s));
}

void cli_groupchat::on_server_disconnect(server_id sid, error err) {
	auto conn = find(sid);
	auto s = print("disconnected from sync server % (%, error=%)", sid, conn ? std::format("{}", conn->current_endpoint()) : "?", err);
	win_.add_info(0, to_wstring(s));
}

void cli_groupchat::on_init(server_chat_id id, error err) {
	std::string msg;
	if(err) {
		msg = print("failed to create chat (id=%, error=%)", to_hex(id.cid), err);
	} else {
		msg = print("created chat with id %", to_hex(id.cid));
	}
	win_.add_info(notice_channel(id.cid), to_wstring(msg));
}

void cli_groupchat::on_change_user(server_chat_id id, sync::users change, error err) {
	std::string msg;
	if(err) {
		msg = print("failed to change user (id=%, error=%)", to_hex(id.cid), err);
	} else {
		msg = print("changed users for chat with id %", to_hex(id.cid));
	}
	win_.add_info(notice_channel(id.cid), to_wstring(msg));
}

void cli_groupchat::on_join(server_chat_id id, sync::users change, error) {
	auto s = print("joined '%'", to_hex(id.cid));
	win_.add_info(notice_channel(id.cid), to_wstring(s));
}

std::string cli_groupchat::time_to_string(time_point time) const {
	return std::format("{:%H:%M:%S}", std::chrono::floor<std::chrono::seconds>(time));
}

void cli_groupchat::on_message(server_chat_id id, msg_data md, msg_change) {
	auto c_opt = map_to_channel(id.cid);
	if(!c_opt) {
		auto conn = find(id.sid);
		c_opt = add_channel(id.cid, conn ? conn->get(id.cid).name() : to_hex(id.cid));
	}
	auto opt_contact = contacts().find(md.sender);
	std::string name = opt_contact ? opt_contact->name() : md.sender.public_key_id().in_hex();
	//auto info = account_info();
	//bool is_me = info && info->me.id().public_key_id() == uid.public_key_id();

	auto s = print("[%] %> %", time_to_string(md.server_time), name, md.message);
	win_.add_message(*c_opt, s);
}

void cli_groupchat::on_file(server_chat_id id, file_entry file, file_change) {
	auto c_opt = map_to_channel(id.cid);
	if(!c_opt) {
		auto conn = find(id.sid);
		c_opt = add_channel(id.cid, conn ? conn->get(id.cid).name() : to_hex(id.cid));
	}
	auto opt_contact = contacts().find(file.sharer);
	std::string name = opt_contact ? opt_contact->name() : file.sharer.public_key_id().in_hex();
	auto s = print("[%] %> shared file #% '%' (% bytes)", time_to_string(file.shared_time), name, file.index, file.name, file.size);
	win_.add_message(*c_opt, s);
}

void cli_groupchat::on_file_state(server_chat_id id, file_id fid, file_state state, error err) {
	auto s = err ? print("file % (%): %", fid, file_state_name(state), err)
		: print("file %: %", fid, file_state_name(state));
	win_.add_info(notice_channel(id.cid), to_wstring(s));
}

void cli_groupchat::on_message_failed(server_chat_id id, message_id mid, error err) {
	auto s = print("message % was refused by the server: %", mid, err);
	win_.add_info(notice_channel(id.cid), to_wstring(s));
}

void cli_groupchat::on_contacting(sync::client::request const& req
		, std::string const& name
		, std::string const& message)
{
	auto s = print("[rid=%] received contacting from '%' (%)", req.id, name, req.sender.id().public_key_id().in_hex());
	win_.add_info(0, to_wstring(s));
}

void cli_groupchat::handle_event(std::unique_ptr<event_system::event_base> ev) {
	dispatch( *ev
			, event_dest<sync::client::events::on_connect>(&cli_groupchat::on_connect)
			, event_dest<sync::client::events::on_disconnect>(&cli_groupchat::on_disconnect)
			, event_dest<sync::client::events::on_contacting>(&cli_groupchat::on_contacting)
			, event_dest<events::on_connect>(&cli_groupchat::on_server_connect)
			, event_dest<events::on_disconnect>(&cli_groupchat::on_server_disconnect)
			, event_dest<events::on_init>(&cli_groupchat::on_init)
			, event_dest<events::on_change_user>(&cli_groupchat::on_change_user)
			, event_dest<events::on_join>(&cli_groupchat::on_join)
			, event_dest<events::on_message>(&cli_groupchat::on_message)
			, event_dest<events::on_message_failed>(&cli_groupchat::on_message_failed)
			, event_dest<events::on_file>(&cli_groupchat::on_file)
			, event_dest<events::on_file_state>(&cli_groupchat::on_file_state) );
}

int cli_groupchat::notice_channel(chat_id const& cid) const {
	return map_to_channel(cid).value_or(0);
}

}