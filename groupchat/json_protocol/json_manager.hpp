#pragma once

#include <securepath/event_system/event_loop.hpp>

#include <functional>
#include <memory>
#include <string>

namespace securepath::groupchat::json_protocol {

class json_manager {
public:
	json_manager(std::function<void(std::string)>);
	~json_manager();

	/// Process command and return result
	std::string process(std::string);

	void close();
private:
	class impl;
	std::unique_ptr<impl> impl_;
	event_system::single_thread_event_loop loop_;
};

}
