#include "cmd_data.hpp"

#include <securepath/util/error.hpp>
#include <securepath/util/string_util.hpp>
#include <cassert>

namespace securepath::groupchat {

cmd_data::cmd_data(std::wstring name, cmd_func f, std::size_t req_args)
: name_(std::move(name))
, func_(std::move(f))
, required_args_(req_args)
{
}

void cmd_data::call(std::vector<std::wstring_view> const& args) const {
	assert(func_);
	if(args.size() < required_args_) {
		throw make_error(errc::invalid_argument, to_string(L"missing argument(s) for /" + name_));
	}
	func_(args);
}

std::wstring cmd_data::name() const {
	return name_;
}

}