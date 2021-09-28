#pragma once

#include <functional>
#include <memory>
#include <string>

namespace securepath::network {
	class context;
}
namespace securepath::event_system {
	class event_loop;
}

namespace securepath::groupchat::json_protocol {

void initialise_logging();

class json_manager {
public:
	json_manager(std::function<void(std::string)>);
	json_manager(network::context& context, std::function<void(std::string)>, std::string path = "");
	~json_manager();

	/// return account information if account exists, otherwise empty json object
	std::string get_account() const;

	/// create account if not already exists, otherwise error
	std::string create_account(std::string_view const&);

	/// connect to the server and update existing chats
	std::string connect();

	/// disconnect
	std::string disconnect();

	/// get list of contacts
	std::string get_contacts(std::string_view const&) const;

	/// add contact
	std::string add_contact(std::string_view const&);

	/// get list of chats
	std::string get_chats(std::string_view const&) const;

	/// create new chat
	std::string create_chat(std::string_view const&);

	/// join existing chat when you have been invited
	std::string join_chat(std::string_view const&);

	/// list members of a chat
	std::string get_chat_members(std::string_view const&) const;

	/// add or remove chat member
	std::string change_chat_member(std::string_view const&);

	/// get messages matching the given criteria (must contain at least the chat id)
	std::string get_messages(std::string_view const&) const;

	/// send message to given chat
	std::string send_message(std::string_view const&);

	/// handle scanned qr code
	std::string handle_qr_code(std::string_view const&);

	void close();
private:
	std::unique_ptr<event_system::event_loop> loop_;

	class impl;
	std::unique_ptr<impl> impl_;
};

}
