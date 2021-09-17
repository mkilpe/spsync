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
	json_manager(network::context& context, std::function<void(std::string)>);
	~json_manager();

	/// Process command and return result
	//std::string process(std::string);

	std::string get_account() const;
	std::string create_account(std::string const&);

	void close();
private:
	std::unique_ptr<event_system::event_loop> loop_;

	class impl;
	std::unique_ptr<impl> impl_;
};

}
