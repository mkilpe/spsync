#include "cli_window.hpp"

#include <securepath/console/attr.hpp>
#include <securepath/log/log.hpp>

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

	auto size = context.screen_size();
	text_area_ = std::make_shared<console::text_window>(console::rect{console::point{0,0}, {size.x, size.y-1}});
	context.add_widget(text_area_);
}

void cli_window::add_line_to_screen(cli_message const& msg) {
	console::scoped_attr color{text_area_->native_handle(),
		msg.type == cli_message::normal ? console::colour_index{1} : console::colour_index{2}};
	text_area_->add_line(msg.msg);
	// note the console system to draw everything next time control returns
	context_.redraw();
}

void cli_window::add_line(int channel, cli_message msg) {
	if(channel == current_channel_) {
		add_line_to_screen(msg);
	}
	history_[channel].push_back(std::move(msg));
}

void cli_window::add_message(int channel, std::wstring msg) {
	add_line(channel, cli_message{std::move(msg), cli_message::normal});
}

void cli_window::add_info(int channel, std::wstring msg) {
	add_line(channel, cli_message{std::move(msg), cli_message::info});
}

void cli_window::change_channel(int channel) {
	current_channel_ = channel;
	//t: change text from history
}

}