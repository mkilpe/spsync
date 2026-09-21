#include "data_downloader.hpp"
#include "action_pump.hpp"

#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <algorithm>
#include <deque>
#include <map>
#include <mutex>
#include <vector>

namespace securepath::sync {
namespace {

/// one data on its way down
struct download {
	data_descriptor descriptor;
	/// chunks missing here and held by the holder, no piece of which was asked for yet
	std::deque<std::uint64_t> wanted;
	/// the chunk being asked for and how far: its pieces are asked in order
	std::optional<std::uint64_t> current;
	std::uint64_t offset{};
	/// chunks on their way in, by chunk number
	std::map<std::uint64_t, incoming_chunk> incoming;
	/// the first error; nothing more is asked, the download ends when the answers are in
	std::optional<error> failure;
	/// pieces asked for without an answer yet
	std::size_t outstanding{};
	/// encrypted octets held here
	std::uint64_t transferred{};
	/// the holder answered the opening
	bool opened{};
	/// chunks missing here that the holder does not have either
	bool holder_incomplete{};
};

using action = action_pump::action;

}

class data_downloader::impl : public std::enable_shared_from_this<impl> {
public:
	impl(record_data_store& store, data_download_channel& channel, data_download_config config
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
		std::vector<data_id> idle;
		for(auto& [id, down] : active_) {
			fill_window(id, down, actions);
			if(down.outstanding == 0) {
				idle.push_back(id);
			}
		}
		// a download that could not start its next chunk ends here: no answer will come for it
		for(auto const& id : idle) {
			finish_if_done(id, active_.at(id));
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
			if(row) {
				active_[id].descriptor = row->descriptor;
				actions.push_back(open_action(row->descriptor));
			} else {
				LOG_WARN("download of a data no stored record names [data_id={}]", to_hex(id));
				notify_done(id, make_error(securepath::errc::no_such_data, "record data not known"));
			}
		}
	}

	static bool all_asked(download const& down) {
		return down.wanted.empty() && !down.current;
	}

	std::uint32_t piece_size() const {
		return std::max<std::uint32_t>(config_.piece_size, 1);
	}

	void fill_window(data_id const& id, download& down, std::vector<action>& actions) {
		while(down.opened && !down.failure && down.outstanding < config_.window && !all_asked(down)) {
			if(!down.current && !begin_next_chunk(id, down)) {
				down.failure = make_error(securepath::errc::invalid_state, "cannot receive a record data chunk");
			} else {
				std::uint64_t const chunk_size = down.descriptor.chunk_enc_size(*down.current);
				auto const size = static_cast<std::uint32_t>(std::min<std::uint64_t>(piece_size(), chunk_size - down.offset));
				++down.outstanding;
				actions.push_back(fetch_action(id, *down.current, down.offset, size));
				down.offset += size;
				if(down.offset >= chunk_size) {
					down.current.reset();
				}
			}
		}
	}

	/// the next wanted chunk becomes the current one, with the staged file it is received into
	bool begin_next_chunk(data_id const& id, download& down) {
		std::uint64_t const chunk_no = down.wanted.front();
		down.wanted.pop_front();
		auto incoming = store_.begin_chunk(id, chunk_no);
		if(incoming) {
			down.incoming.emplace(chunk_no, std::move(*incoming));
			down.current = chunk_no;
			down.offset = 0;
		}
		return incoming.has_value();
	}

	action open_action(data_descriptor descriptor) {
		return [self = shared_from_this(), generation = generation_, descriptor = std::move(descriptor)] {
			std::weak_ptr<impl> weak = self;
			auto const id = descriptor.manifest_digest;
			try {
				self->channel_.open_download(descriptor, [weak, generation, id](util::result<download_info> info) {
					if(auto s = weak.lock()) {
						s->on_opened(generation, id, std::move(info));
					}
				});
			} catch(...) {
				self->on_opened(generation, id, util::result<download_info>{util::current_exception_error()});
			}
		};
	}

	action fetch_action(data_id id, std::uint64_t chunk_no, std::uint64_t offset, std::uint32_t size) {
		return [self = shared_from_this(), generation = generation_, id = std::move(id), chunk_no, offset, size] {
			std::weak_ptr<impl> weak = self;
			try {
				self->channel_.fetch_piece(id, chunk_no, offset, size, [weak, generation, id, chunk_no, offset](util::result<octet_vector> piece) {
					if(auto s = weak.lock()) {
						s->on_piece(generation, id, chunk_no, offset, std::move(piece));
					}
				});
			} catch(...) {
				self->on_piece(generation, id, chunk_no, offset, util::result<octet_vector>{util::current_exception_error()});
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

	void notify_progress(data_id const& id, download const& down) {
		if(progress_) {
			notifications_.push_back([progress = progress_, id, transferred = down.transferred, total = down.descriptor.enc_size] {
				progress(id, transferred, total);
			});
		}
	}

	/// the download ends when nothing is left to ask for and every answer is in
	void finish_if_done(data_id const& id, download const& down) {
		if(down.outstanding == 0 && (down.failure || (down.opened && all_asked(down)))) {
			std::optional<error> result = down.failure;
			if(!result && down.holder_incomplete) {
				// RD7 remote_not_complete: the upload is still in progress over there
				result = make_error(protocol::errc::data_not_held, "the holder has only a part of the data yet");
			}
			notify_done(id, std::move(result));
			active_.erase(id);
		}
	}

	/// what to fetch: the chunks missing here that the holder has
	void plan(data_id const& id, download& down, download_info const& info) {
		auto const row = store_.find(id);
		if(!store_.set_manifest(id, info.manifest) || !row) {
			LOG_WARN("the holder's manifest is not the one the record commits to [data_id={}]", to_hex(id));
			down.failure = make_error(protocol::errc::invalid_data_manifest);
		} else {
			for(std::uint64_t no = 0; no != down.descriptor.chunk_count(); ++no) {
				if(row->have.test(no)) {
					down.transferred += down.descriptor.chunk_enc_size(no);
				} else if(info.have.test(no)) {
					down.wanted.push_back(no);
				} else {
					down.holder_incomplete = true;
				}
			}
			down.opened = true;
			notify_progress(id, down);
		}
	}

	/// one piece into its chunk; the piece that completes the chunk gets it verified
	void take_piece(download& down, std::uint64_t chunk_no, std::uint64_t offset, octet_vector const& piece) {
		auto it = down.incoming.find(chunk_no);
		bool ok = it != down.incoming.end() && it->second.append(offset, piece);
		if(ok && it->second.complete()) {
			ok = it->second.finish();
			down.incoming.erase(it);
		}
		if(ok) {
			down.transferred += piece.size();
		} else if(!down.failure) {
			down.incoming.erase(chunk_no);
			down.failure = make_error(protocol::errc::invalid_data_chunk, "received a chunk that is not the manifest's");
		}
	}

	// -- answers of the channel, any thread --

	void on_opened(std::uint64_t generation, data_id const& id, util::result<download_info> info) {
		{
			std::unique_lock lock{mutex_};
			auto it = active_.find(id);
			if(generation == generation_ && it != active_.end()) {
				if(info) {
					plan(id, it->second, info.value());
				} else {
					it->second.failure = info.get_error();
				}
				finish_if_done(id, it->second);
			}
		}
		pump();
	}

	void on_piece(std::uint64_t generation, data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, util::result<octet_vector> piece) {
		{
			std::unique_lock lock{mutex_};
			auto it = active_.find(id);
			if(generation == generation_ && it != active_.end()) {
				auto& down = it->second;
				--down.outstanding;
				if(!piece) {
					LOG_INFO("download of a record data piece failed [data_id={}, chunk={}]: {}", to_hex(id), chunk_no, piece.get_error());
					if(!down.failure) {
						down.failure = piece.get_error();
					}
				} else if(!down.failure) {
					take_piece(down, chunk_no, offset, piece.value());
					notify_progress(id, down);
				}
				finish_if_done(id, down);
			}
		}
		pump();
	}

private:
	record_data_store& store_;
	data_download_channel& channel_;
	data_download_config const config_;
	done_callback const done_;
	progress_callback const progress_;

	mutable std::mutex mutex_;
	std::deque<data_id> queue_;
	std::map<data_id, download> active_;
	std::vector<action> notifications_;
	/// answers to calls made before a reset carry an older generation and are ignored
	std::uint64_t generation_{};
	action_pump pump_;
};

data_downloader::data_downloader(record_data_store& store, data_download_channel& channel, data_download_config config
	, done_callback done, progress_callback progress)
: impl_(std::make_shared<impl>(store, channel, config, std::move(done), std::move(progress)))
{
}

data_downloader::~data_downloader() {
	impl_->reset();
}

bool data_downloader::enqueue(data_id const& id) {
	return impl_->enqueue(id);
}

void data_downloader::reset() {
	impl_->reset();
}

std::size_t data_downloader::queued() const {
	return impl_->queued();
}

std::size_t data_downloader::in_flight() const {
	return impl_->in_flight();
}

}
