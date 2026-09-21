#include "data_uploader.hpp"
#include "action_pump.hpp"

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <algorithm>
#include <deque>
#include <map>
#include <mutex>
#include <vector>

namespace securepath::sync {
namespace {

/// one data on its way
struct upload {
	data_descriptor descriptor;
	/// chunks the holder lacks and no piece of which was sent yet
	std::deque<std::uint64_t> missing;
	/// the chunk being sent and how far: its pieces go in order
	std::optional<std::uint64_t> current;
	std::uint64_t offset{};
	/// the first error; nothing more is sent, the upload ends when the answers are in
	std::optional<error> failure;
	/// pieces sent without an answer yet
	std::size_t outstanding{};
	/// encrypted octets known to be at the holder
	std::uint64_t transferred{};
	/// the holder answered the manifest
	bool opened{};
};

using action = action_pump::action;

}

class data_uploader::impl : public std::enable_shared_from_this<impl> {
public:
	impl(record_data_store& store, data_channel& channel, data_upload_config config
		, done_callback done, progress_callback progress)
	: store_(store)
	, channel_(channel)
	, config_(config)
	, done_(std::move(done))
	, progress_(std::move(progress))
	{}

	bool enqueue(data_id const& id) {
		bool added = false;
		{
			std::unique_lock lock{mutex_};
			added = !active_.contains(id) && std::find(queue_.begin(), queue_.end(), id) == queue_.end();
			if(added) {
				queue_.push_back(id);
			}
		}
		if(added) {
			pump();
		}
		return added;
	}

	void reset() {
		std::unique_lock lock{mutex_};
		++generation_;
		queue_.clear();
		active_.clear();
		notifications_.clear();
	}

	std::size_t queued() const {
		std::unique_lock lock{mutex_};
		return queue_.size();
	}

	std::size_t in_flight() const {
		std::unique_lock lock{mutex_};
		return active_.size();
	}

private:
	/// do what the state asks for, outside the lock (see action_pump)
	void pump() {
		pump_.run([this] {
			std::unique_lock lock{mutex_};
			return collect();
		});
	}

	// requires the mutex, as everything below down to the channel answers
	std::vector<action> collect() {
		std::vector<action> actions;
		start_queued(actions);
		for(auto& [id, up] : active_) {
			fill_window(id, up, actions);
		}
		for(auto& n : notifications_) {
			actions.push_back(std::move(n));
		}
		notifications_.clear();
		return actions;
	}

	void start_queued(std::vector<action>& actions) {
		while(active_.size() < config_.max_datas && !queue_.empty()) {
			data_id id = std::move(queue_.front());
			queue_.pop_front();
			auto const row = store_.find(id);
			auto manifest = store_.manifest(id);
			if(row && manifest) {
				active_[id] = upload{row->descriptor};
				actions.push_back(open_action(row->descriptor, std::move(*manifest)));
			} else {
				LOG_WARN("upload of a data the store does not hold [data_id={}]", to_hex(id));
				notify_done(id, make_error(securepath::errc::no_such_data, "record data not held"));
			}
		}
	}

	/// nothing of the data is left to send (pieces may still be out)
	static bool all_sent(upload const& up) {
		return up.missing.empty() && !up.current;
	}

	void fill_window(data_id const& id, upload& up, std::vector<action>& actions) {
		while(up.opened && !up.failure && up.outstanding < config_.window && !all_sent(up)) {
			if(!up.current) {
				up.current = up.missing.front();
				up.missing.pop_front();
				up.offset = 0;
			}
			std::uint64_t const chunk_size = up.descriptor.chunk_enc_size(*up.current);
			auto const size = static_cast<std::size_t>(std::min<std::uint64_t>(piece_size(), chunk_size - up.offset));
			++up.outstanding;
			actions.push_back(send_action(id, *up.current, up.offset, size));
			up.offset += size;
			if(up.offset >= chunk_size) {
				up.current.reset();
			}
		}
	}

	std::uint32_t piece_size() const {
		return std::max<std::uint32_t>(config_.piece_size, 1);
	}

	action open_action(data_descriptor descriptor, data_manifest manifest) {
		return [self = shared_from_this(), generation = generation_, descriptor = std::move(descriptor), manifest = std::move(manifest)] {
			std::weak_ptr<impl> weak = self;
			auto const id = descriptor.manifest_digest;
			try {
				self->channel_.open_upload(descriptor, manifest, [weak, generation, id](util::result<have_bitmap> have) {
					if(auto s = weak.lock()) {
						s->on_opened(generation, id, std::move(have));
					}
				});
			} catch(...) {
				self->on_opened(generation, id, util::result<have_bitmap>{util::current_exception_error()});
			}
		};
	}

	/// read one piece from the chunk file and send it: only the piece is ever in memory
	action send_action(data_id id, std::uint64_t chunk_no, std::uint64_t offset, std::size_t size) {
		return [self = shared_from_this(), generation = generation_, id = std::move(id), chunk_no, offset, size] {
			std::weak_ptr<impl> weak = self;
			try {
				auto piece = self->store_.read_chunk_piece(id, chunk_no, offset, size);
				if(!piece) {
					throw make_error(securepath::errc::no_such_data, "record data chunk not held");
				}
				self->channel_.send_piece(id, chunk_no, offset, std::move(*piece), [weak, generation, id, chunk_no, size](std::optional<error> err) {
					if(auto s = weak.lock()) {
						s->on_piece_sent(generation, id, chunk_no, size, std::move(err));
					}
				});
			} catch(...) {
				self->on_piece_sent(generation, id, chunk_no, size, util::current_exception_error());
			}
		};
	}

	void notify_done(data_id const& id, std::optional<error> err) {
		notifications_.push_back([done = done_, id, err = std::move(err)] {
			if(done) {
				done(id, err);
			}
		});
	}

	void notify_progress(data_id const& id, upload const& up) {
		if(progress_) {
			notifications_.push_back([progress = progress_, id, transferred = up.transferred, total = up.descriptor.enc_size] {
				progress(id, transferred, total);
			});
		}
	}

	/// the upload ends when nothing is left to send and every answer is in
	void finish_if_done(data_id const& id, upload const& up) {
		if(up.outstanding == 0 && (up.failure || (up.opened && all_sent(up)))) {
			notify_done(id, up.failure);
			active_.erase(id);
		}
	}

	// -- answers of the channel, any thread --

	void on_opened(std::uint64_t generation, data_id const& id, util::result<have_bitmap> have) {
		{
			std::unique_lock lock{mutex_};
			auto it = active_.find(id);
			if(generation == generation_ && it != active_.end()) {
				auto& up = it->second;
				if(have) {
					up.opened = true;
					for(std::uint64_t no = 0; no != up.descriptor.chunk_count(); ++no) {
						if(have->test(no)) {
							up.transferred += up.descriptor.chunk_enc_size(no);
						} else {
							up.missing.push_back(no);
						}
					}
					notify_progress(id, up);
				} else {
					up.failure = have.get_error();
				}
				finish_if_done(id, up);
			}
		}
		pump();
	}

	void on_piece_sent(std::uint64_t generation, data_id const& id, std::uint64_t chunk_no, std::size_t size, std::optional<error> err) {
		{
			std::unique_lock lock{mutex_};
			auto it = active_.find(id);
			if(generation == generation_ && it != active_.end()) {
				auto& up = it->second;
				--up.outstanding;
				if(err) {
					LOG_INFO("upload of a record data chunk failed [data_id={}, chunk={}]: {}", to_hex(id), chunk_no, *err);
					if(!up.failure) {
						up.failure = std::move(err);
					}
				} else {
					up.transferred += size;
					notify_progress(id, up);
				}
				finish_if_done(id, up);
			}
		}
		pump();
	}

private:
	record_data_store& store_;
	data_channel& channel_;
	data_upload_config const config_;
	done_callback const done_;
	progress_callback const progress_;

	mutable std::mutex mutex_;
	/// waiting datas in the order they were queued
	std::deque<data_id> queue_;
	std::map<data_id, upload> active_;
	/// callbacks owed, made by the next round without the lock
	std::vector<action> notifications_;
	/// answers to calls made before a reset carry an older generation and are ignored
	std::uint64_t generation_{};
	action_pump pump_;
};

data_uploader::data_uploader(record_data_store& store, data_channel& channel, data_upload_config config
	, done_callback done, progress_callback progress)
: impl_(std::make_shared<impl>(store, channel, config, std::move(done), std::move(progress)))
{
}

data_uploader::~data_uploader() {
	impl_->reset();
}

bool data_uploader::enqueue(data_id const& id) {
	return impl_->enqueue(id);
}

void data_uploader::reset() {
	impl_->reset();
}

std::size_t data_uploader::queued() const {
	return impl_->queued();
}

std::size_t data_uploader::in_flight() const {
	return impl_->in_flight();
}

}
