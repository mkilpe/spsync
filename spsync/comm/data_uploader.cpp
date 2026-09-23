#include "data_uploader.hpp"
#include "transfer_queue.hpp"

namespace securepath::sync {
namespace {

/// one data on its way up: nothing beyond what every transfer keeps
struct upload : transfer_state {};

}

class data_uploader::impl : public transfer_queue<upload> {
public:
	impl(record_data_store& store, data_channel& channel, transfer_config config
		, done_callback done, progress_callback progress)
	: transfer_queue("upload", store, config, std::move(done), std::move(progress))
	, channel_(channel)
	{}

private:
	std::optional<error> start(data_id const& id, upload& up, action& opening) override {
		auto const row = read_store(id, [&] { return store().find(id); });
		auto manifest = read_store(id, [&] { return store().manifest(id); });
		if(!row || !manifest) {
			return make_error(securepath::errc::no_such_data, "record data not held");
		}
		up.cursor = piece_cursor{row->descriptor};
		opening = open_action(row->descriptor, std::move(*manifest));
		return std::nullopt;
	}

	action piece_action(data_id const& id, piece_range const& piece) override {
		return send_action(id, piece);
	}

	action open_action(data_descriptor descriptor, data_manifest manifest) {
		return [self = self_as<impl>(), generation = generation(), descriptor = std::move(descriptor), manifest = std::move(manifest)] {
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
	action send_action(data_id id, piece_range piece) {
		return [self = self_as<impl>(), generation = generation(), id = std::move(id), piece] {
			std::weak_ptr<impl> weak = self;
			try {
				auto bytes = self->store().read_chunk_piece(id, piece.chunk_no, piece.offset, piece.size);
				if(!bytes) {
					throw make_error(securepath::errc::no_such_data, "record data chunk not held");
				}
				self->channel_.send_piece(id, piece.chunk_no, piece.offset, std::move(*bytes), [weak, generation, id, piece](std::optional<error> err) {
					if(auto s = weak.lock()) {
						s->on_piece_sent(generation, id, piece, std::move(err));
					}
				});
			} catch(...) {
				self->on_piece_sent(generation, id, piece, util::current_exception_error());
			}
		};
	}

	// -- answers of the channel, any thread --

	/// the holder's answer to the manifest: what it lacks is what goes
	void on_opened(std::uint64_t generation, data_id const& id, util::result<have_bitmap> const& have) {
		opened(generation, id, have, [](upload& up, have_bitmap const& held) {
			auto const& descriptor = up.cursor.descriptor();
			for(std::uint64_t no = 0; no != descriptor.chunk_count(); ++no) {
				if(held.test(no)) {
					up.transferred += descriptor.chunk_enc_size(no);
				} else {
					up.cursor.add(no);
				}
			}
		});
	}

	void on_piece_sent(std::uint64_t generation, data_id const& id, piece_range const& piece, std::optional<error> err) {
		piece_answered(generation, id, piece.chunk_no, std::move(err), [&](upload& up) { up.transferred += piece.size; });
	}

private:
	data_channel& channel_;
};

data_uploader::data_uploader(record_data_store& store, data_channel& channel, transfer_config config
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
