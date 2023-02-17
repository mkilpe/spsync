#pragma once

#include <securepath/console/context.hpp>
#include <securepath/console/label.hpp>
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

	int add_channel(std::wstring name);
	void add_message(int channel, std::wstring msg);
	void add_info(int channel, std::wstring msg);

	/// utf8 versions
	void add_message(int channel, std::string msg);
	void add_info(int channel, std::string msg);

	int current_channel() const;
	void change_channel(std::string text, int channel);

private:
	void add_line_to_screen(cli_message const& msg);
	void add_line(int channel, cli_message msg);
	void update_status_bar();
private:
	struct channel_info {
		std::wstring name;
		std::deque<cli_message> history;
		bool unseen{};
	};
	console::context& context_;
	int current_channel_{};
	std::map<int, channel_info> channels_;
	std::shared_ptr<console::text_window> text_area_;
	std::shared_ptr<console::label> status_area_;
	std::string status_text_;
};

}