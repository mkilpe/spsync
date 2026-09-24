#include "data_downloader.hpp"
#include "transfer_queue.hpp"

#include <spsync/protocol/error.hpp>

namespace securepath::sync {
namespace {

/// one data on its way down
struct download : transfer_state {
	/// chunks on their way in, by chunk number
	std::map<std::uint64_t, incoming_chunk> incoming;
	/// chunks missing here that the holder does not have either
	bool holder_incomplete{};
};

}

class data_downloader::impl : public transfer_queue<download> {
public:
	impl(record_data_store& store, data_download_channel& channel, transfer_config config
		, done_callback done, progress_callback progress, asio::io_context* io)
	: transfer_queue("download", store, config, std::move(done), std::move(progress), io)
	, channel_(channel)
	{}

private:
	std::optional<error> start(data_id const& id, download& down, action& opening) override {
		auto const row = read_store(id, [&] { return store().find(id); });
		if(!row) {
			return make_error(securepath::errc::no_such_data, "record data not known");
		}
		down.cursor = piece_cursor{row->descriptor};
		opening = open_action(row->descriptor);
		return std::nullopt;
	}

	/// the staged file the chunk is received into
	std::optional<error> begin_chunk(data_id const& id, download& down, std::uint64_t chunk_no) override {
		std::optional<error> ret;
		auto incoming = staged_chunk(id, chunk_no);
		if(incoming) {
			down.incoming.emplace(chunk_no, std::move(*incoming));
		} else {
			ret = make_error(securepath::errc::invalid_state, "cannot receive a record data chunk");
		}
		return ret;
	}

	action piece_action(data_id const& id, piece_range const& piece) override {
		return fetch_action(id, piece);
	}

	std::optional<error> outcome(download const& down) const override {
		std::optional<error> result = down.failure;
		if(!result && down.holder_incomplete) {
			// RD7 remote_not_complete: the upload is still in progress over there
			result = make_error(protocol::errc::data_not_held, "the holder has only a part of the data yet");
		}
		return result;
	}

	/// none when the store fails as well (an incoming chunk moves but is not assigned:
	/// every outcome is returned where it is known)
	std::optional<incoming_chunk> staged_chunk(data_id const& id, std::uint64_t chunk_no) {
		try {
			return store().begin_chunk(id, chunk_no);
		} catch(std::exception const& ex) {
			LOG_WARN("cannot receive a record data chunk [data_id={}, chunk={}]: {}", to_hex(id), chunk_no, ex.what());
		}
		return std::nullopt;
	}

	action open_action(data_descriptor descriptor) {
		return [self = self_as<impl>(), generation = generation(), descriptor = std::move(descriptor)] {
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

	action fetch_action(data_id id, piece_range piece) {
		return [self = self_as<impl>(), generation = generation(), id = std::move(id), piece] {
			std::weak_ptr<impl> weak = self;
			try {
				self->channel_.fetch_piece(id, piece.chunk_no, piece.offset, piece.size, [weak, generation, id, piece](util::result<octet_vector> bytes) {
					if(auto s = weak.lock()) {
						s->on_piece(generation, id, piece, std::move(bytes));
					}
				});
			} catch(...) {
				self->on_piece(generation, id, piece, util::result<octet_vector>{util::current_exception_error()});
			}
		};
	}

	/// what to fetch: the chunks missing here that the holder has
	void plan(data_id const& id, download& down, download_info const& info) {
		auto const row = store().find(id);
		if(!store().set_manifest(id, info.manifest) || !row) {
			LOG_WARN("the holder's manifest is not the one the record commits to [data_id={}]", to_hex(id));
			down.failure = make_error(protocol::errc::invalid_data_manifest);
		} else {
			auto const& descriptor = down.cursor.descriptor();
			for(std::uint64_t no = 0; no != descriptor.chunk_count(); ++no) {
				if(row->have.test(no)) {
					down.transferred += descriptor.chunk_enc_size(no);
				} else if(info.have.test(no)) {
					down.cursor.add(no);
				} else {
					down.holder_incomplete = true;
				}
			}
		}
	}

	/// one piece into its chunk; the piece that completes the chunk gets it verified
	void take_piece(download& down, piece_range const& piece, octet_vector const& bytes) {
		auto it = down.incoming.find(piece.chunk_no);
		bool ok = it != down.incoming.end() && it->second.append(piece.offset, bytes);
		if(ok && it->second.complete()) {
			ok = it->second.finish();
			down.incoming.erase(it);
		}
		if(ok) {
			down.transferred += bytes.size();
		} else if(!down.failure) {
			down.incoming.erase(piece.chunk_no);
			down.failure = make_error(protocol::errc::invalid_data_chunk, "received a chunk that is not the manifest's");
		}
	}

	// -- answers of the channel, any thread --

	void on_opened(std::uint64_t generation, data_id const& id, util::result<download_info> const& info) {
		opened(generation, id, info, [&](download& down, download_info const& answer) { plan(id, down, answer); });
	}

	void on_piece(std::uint64_t generation, data_id const& id, piece_range const& piece, util::result<octet_vector> const& bytes) {
		auto err = bytes ? std::nullopt : std::optional<error>{bytes.get_error()};
		piece_answered(generation, id, piece.chunk_no, std::move(err), [&](download& down) { take_piece(down, piece, bytes.value()); });
	}

private:
	data_download_channel& channel_;
};

data_downloader::data_downloader(record_data_store& store, data_download_channel& channel, transfer_config config
	, done_callback done, progress_callback progress, asio::io_context* io)
: impl_(std::make_shared<impl>(store, channel, config, std::move(done), std::move(progress), io))
{
}

data_downloader::~data_downloader() {
	impl_->close();
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
