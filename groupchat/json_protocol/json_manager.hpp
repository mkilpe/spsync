#pragma once

#include <functional>
#include <memory>
#include <string>

namespace securepath::groupchat::json_protocol {

void initialise_logging();

class json_manager {
public:
	json_manager(std::function<void(std::string)>);
	~json_manager();

	/// Process command and return result
	//std::string process(std::string);

	std::string get_account() const;
	std::string create_account(std::string const&);

	void close();
private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}
