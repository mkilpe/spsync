#pragma once

#include <securepath/console/context.hpp>
#include <securepath/console/text_window.hpp>

#include <map>
#include <deque>
#include <string>

namespace securepath::groupchat {

struct cli_message {
	std::wstring msg;
	enum { normal, info } type;
};

class cli_window {
public:
	cli_window(console::context&);

	void add_message(int channel, std::wstring msg);
	void add_info(int channel, std::wstring msg);
	void change_channel(int channel);
private:
	void add_line_to_screen(cli_message const& msg);
	void add_line(int channel, cli_message msg);
private:
	int current_channel_{};
	std::map<int, std::deque<cli_message>> history_;
	std::shared_ptr<console::text_window> text_area_;
};

}