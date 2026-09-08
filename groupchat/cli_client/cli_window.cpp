#include "cli_window.hpp"

#include <securepath/console/attr.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/string_util.hpp>

#include <stdexcept>

namespace securepath::groupchat {

cli_window::cli_window(console::context& context)
: context_(context)
{
	if(!console::make_colour_pair(console::colour_index{1}, console::colour::white, console::colour::black)) {
		throw std::runtime_error("failed to initialise colours");
	}
	if(!console::make_colour_pair(console::colour_index{2}, console::colour::green, console::colour::black)) {
		throw std::runtime_error("failed to initialise colours");
	}
	if(!console::make_colour_pair(console::colour_index{3}, console::colour::white, console::colour::blue)) {
		throw std::runtime_error("failed to initialise colours");
	}

	//t: check size is big enough, handle resizing
	auto size = context.screen_size();
	text_area_ = std::make_shared<console::text_window>(console::rect{console::point{0,0}, {size.x, size.y-2}});
	status_area_ = std::make_shared<console::label>(console::point{0, size.y-1}, size.x);
	status_area_->set_attr(console::colour_index{3});
	context.add_widget(text_area_);
	context.add_widget(status_area_);
}

void cli_window::add_line_to_screen(cli_message const& msg) {
	console::scoped_attr color{text_area_->native_handle(),
		msg.type == cli_message::normal ? console::colour_index{1} : console::colour_index{2}};
	text_area_->add_line(msg.msg);
}

void cli_window::add_line(int channel, cli_message msg) {
	auto c = channels_.find(channel);
	if(c == channels_.end()) {
		throw std::runtime_error("no such channel");
	}
	if(channel == current_channel_) {
		add_line_to_screen(msg);
	} else {
		c->second.unseen = true;
	}
	c->second.history.push_back(std::move(msg));
	update_status_bar();
}

int cli_window::add_channel(std::wstring name) {
	int i = 0;
	for(;i != std::numeric_limits<int>::max(); ++i) {
		if(channels_.count(i) == 0) {
			channels_[i] = channel_info{std::move(name)};
			return i;
		}
	}
	throw std::runtime_error("too many channels");
}

void cli_window::add_message(int channel, std::wstring msg) {
	add_line(channel, cli_message{std::move(msg), cli_message::normal});
}

void cli_window::add_info(int channel, std::wstring msg) {
	add_line(channel, cli_message{std::move(msg), cli_message::info});
}

void cli_window::add_message(int channel, std::string msg) {
	add_message(channel, to_wstring(msg));
}

void cli_window::add_info(int channel, std::string msg) {
	add_info(channel, to_wstring(msg));
}

void cli_window::change_channel(std::string text, int channel) {
	auto c = channels_.find(channel);
	if(c == channels_.end()) {
		throw std::runtime_error("no such channel");
	}
	current_channel_ = channel;
	status_text_ = std::move(text);
	c->second.unseen = false;

	text_area_->clear();
	for(auto&& m : c->second.history) {
		add_line_to_screen(m);
	}
	update_status_bar();
}

void cli_window::update_status_bar() {
	//t: check the status length fits to screen
	std::string status;
	for(auto&& c : channels_) {
		if(c.second.unseen) {
			if(!status.empty()) {
				status += ",";
			}
			status += std::to_string(c.first);
		}
	}
	status_area_->set_text(
		to_wstring("(" + std::to_string(current_channel_) + ") " +
		status_text_ + " [" + status +  "]"));

	context_.redraw();
}

int cli_window::current_channel() const {
	return current_channel_;
}

}