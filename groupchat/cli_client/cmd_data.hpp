// SPDX-License-Identifier: MIT

#pragma once

#include <functional>
#include <string>
#include <vector>

namespace securepath::groupchat {

using cmd_func = std::function<void (std::vector<std::wstring_view> const&)>;

class cmd_data {
public:
	cmd_data(std::wstring name, cmd_func, std::size_t req_args = 0);

	void call(std::vector<std::wstring_view> const&) const;

	std::wstring name() const;
	void show_help(std::function<void(std::wstring)> out) const;
private:
	std::wstring name_;
	cmd_func func_;
	std::size_t required_args_;
};

}