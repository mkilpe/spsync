#include "piece_cursor.hpp"

#include <algorithm>

namespace securepath::sync {

piece_cursor::piece_cursor(data_descriptor descriptor)
: descriptor_(std::move(descriptor))
{
}

void piece_cursor::add(std::uint64_t chunk_no) {
	pending_.push_back(chunk_no);
}

bool piece_cursor::done() const {
	return pending_.empty() && !current_;
}

std::optional<std::uint64_t> piece_cursor::starting_chunk() const {
	std::optional<std::uint64_t> ret;
	if(!current_ && !pending_.empty()) {
		ret = pending_.front();
	}
	return ret;
}

std::optional<piece_range> piece_cursor::next(std::uint32_t piece_size) {
	std::optional<piece_range> ret;
	if(!current_ && !pending_.empty()) {
		current_ = pending_.front();
		pending_.pop_front();
		offset_ = 0;
	}
	if(current_) {
		auto const chunk = descriptor_.chunk_enc_size(*current_);
		auto const size = static_cast<std::uint32_t>(std::min<std::uint64_t>(std::max<std::uint32_t>(piece_size, 1), chunk - offset_));
		ret = piece_range{*current_, offset_, size};
		offset_ += size;
		if(offset_ >= chunk) {
			current_.reset();
		}
	}
	return ret;
}

}
