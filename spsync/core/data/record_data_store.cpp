#include "record_data_store.hpp"
#include "chunk_files.hpp"
#include "data_decryptor.hpp"

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>
#include <securepath/util/error.hpp>

#include <algorithm>
#include <cstring>
#include <mutex>

namespace securepath::sync {

/// what the store, its handles and its writers share
class record_data_store_impl {
public:
	record_data_store_impl(database::connection_ptr db, std::filesystem::path root)
	: table(std::move(db))
	, files(std::move(root))
	{
		// whatever an interrupted creation left behind
		files.clear_staging();
	}

	/// a held encrypted chunk; a chunk the bitmap promises but the disk lost is dropped
	std::optional<octet_vector> read_chunk(data_id const& id, std::uint64_t chunk_no) {
		std::unique_lock lock{mutex};
		std::optional<octet_vector> ret;
		auto row = table.find(id);
		if(row && row->have.test(chunk_no)) {
			ret = files.read(id, chunk_no);
			if(!ret) {
				LOG_WARN("record data chunk lost [data_id={}, chunk={}]", to_hex(id), chunk_no);
				drop_chunk(*row, chunk_no);
			}
		}
		return ret;
	}

	/**
	 * A held chunk did not decrypt (RD3). When it is not the chunk the manifest names
	 * the disk rotted it: drop and refetch. Otherwise the author committed to bytes
	 * that do not authenticate: the data is invalid for good.
	 */
	void chunk_failed(data_id const& id, std::uint64_t chunk_no, octet_span encrypted) {
		std::unique_lock lock{mutex};
		auto row = table.find(id);
		if(row) {
			auto const manifest = table.manifest(row->local_id);
			if(manifest && !manifest->verify_chunk(chunk_no, encrypted)) {
				LOG_WARN("record data chunk corrupted [data_id={}, chunk={}]", to_hex(id), chunk_no);
				drop_chunk(*row, chunk_no);
			} else {
				LOG_WARN("record data does not authenticate [data_id={}, chunk={}]", to_hex(id), chunk_no);
				table.set_state(row->local_id, record_data_state::invalid);
			}
		}
	}

	/// the staged chunks of a writer become a held, upload_pending data
	void register_created(std::string const& stage, encrypted_data_result const& result) {
		std::unique_lock lock{mutex};
		// the row first: a crash in between leaves an unreferenced row for
		// remove_unreferenced, never chunk files nothing knows of
		auto const local_id = table.ensure(result.descriptor);
		table.set_manifest(local_id, result.manifest);
		table.set_state(local_id, record_data_state::upload_pending);
		files.commit_staging(stage, result.descriptor.manifest_digest);

		have_bitmap have{result.descriptor.chunk_count()};
		have.set_all();
		table.set_have(local_id, have);
	}

	/// keep a chunk that verified against the manifest
	void add_chunk(data_state_row row, std::uint64_t chunk_no, octet_span encrypted) {
		if(!row.have.test(chunk_no)) {
			files.write(row.descriptor.manifest_digest, chunk_no, encrypted);
			row.have.set(chunk_no);
			table.set_have(row.local_id, row.have);
			if(row.have.complete() && row.state != record_data_state::upload_pending) {
				table.set_state(row.local_id, record_data_state::in_sync);
			}
		}
	}

private:
	// requires the mutex
	void drop_chunk(data_state_row& row, std::uint64_t chunk_no) {
		if(row.state == record_data_state::upload_pending) {
			// nobody else has it yet: there is nothing to refetch from
			table.set_state(row.local_id, record_data_state::invalid);
		} else {
			files.remove_chunk(row.descriptor.manifest_digest, chunk_no);
			row.have.set(chunk_no, false);
			table.set_have(row.local_id, row.have);
			table.set_state(row.local_id, record_data_state::download_pending);
		}
	}

public:
	std::mutex mutex;
	data_state_table table;
	chunk_files files;
};

namespace {

/// record_data over the store: decrypts and verifies chunk-wise on the way out
class stored_record_data : public record_data {
public:
	stored_record_data(std::shared_ptr<record_data_store_impl> store, std::uint64_t local_id
		, std::vector<data_decryptor> decryptors)
	: store_(std::move(store))
	, local_id_(local_id)
	, id_(decryptors.front().descriptor().manifest_digest)
	, plain_size_(decryptors.front().header().plain_size)
	, chunk_size_(decryptors.front().descriptor().chunk_size)
	, decryptors_(std::move(decryptors))
	{}

	std::uint64_t local_id() const override {
		return local_id_;
	}

	std::uint64_t size() const override {
		return plain_size_;
	}

	/// the octets of the data in held chunks; they need not be contiguous, read() stops at a gap
	std::uint64_t available_size() const override {
		std::uint64_t ret = 0;
		auto const row = store_->table.find(local_id_);
		if(row) {
			std::unique_lock lock{mutex_};
			for(std::uint64_t no = 0; no != row->have.size(); ++no) {
				if(row->have.test(no)) {
					ret += decryptors_.front().chunk_plain_size(no);
				}
			}
		}
		return ret;
	}

	std::uint64_t read(std::uint64_t offset, std::uint8_t* buffer, std::uint64_t size) override {
		std::unique_lock lock{mutex_};
		std::uint64_t done = 0;
		bool ok = chunk_size_ != 0;
		while(ok && done < size && offset + done < plain_size_) {
			std::uint64_t const pos = offset + done;
			std::uint64_t const n = load(pos / chunk_size_) ? copy_cached(pos % chunk_size_, buffer + done, size - done) : 0;
			done += n;
			ok = n != 0;
		}
		return done;
	}

	/// a stored data is what its descriptor says: it is created through a data_writer
	std::uint64_t write(std::uint64_t, std::uint8_t const*, std::uint64_t) override {
		throw make_error(sync::errc::constraint_violation, "stored record data is immutable");
	}

	record_data_state state() const override {
		auto const row = store_->table.find(local_id_);
		return row ? row->state : record_data_state::invalid;
	}

	void set_state(record_data_state state) override {
		store_->table.set_state(local_id_, state);
	}

	void remove_data() override;

private:
	/// the key candidate that authenticates goes first and stays there
	std::optional<octet_vector> decrypt(std::uint64_t chunk_no, octet_span encrypted) {
		std::optional<octet_vector> ret;
		for(std::size_t i = 0; !ret && i != decryptors_.size(); ++i) {
			ret = decryptors_[i].decrypt(chunk_no, encrypted);
			if(ret && i != 0) {
				std::swap(decryptors_[0], decryptors_[i]);
			}
		}
		return ret;
	}

	/// copy out of the cached chunk from the given position in it, returns the octets copied
	std::uint64_t copy_cached(std::uint64_t in_chunk, std::uint8_t* buffer, std::uint64_t max) const {
		std::uint64_t n = 0;
		if(in_chunk < cached_.size()) {
			n = std::min<std::uint64_t>(max, cached_.size() - in_chunk);
			std::memcpy(buffer, cached_.data() + in_chunk, n);
		}
		return n;
	}

	/// make the chunk the cached one; false when it is not held or does not decrypt
	bool load(std::uint64_t chunk_no) {
		bool ok = cached_no_ == chunk_no;
		if(!ok) {
			auto const encrypted = store_->read_chunk(id_, chunk_no);
			if(encrypted) {
				auto plain = decrypt(chunk_no, *encrypted);
				if(plain) {
					cached_ = std::move(*plain);
					cached_no_ = chunk_no;
					ok = true;
				} else {
					store_->chunk_failed(id_, chunk_no, *encrypted);
				}
			}
		}
		return ok;
	}

private:
	std::shared_ptr<record_data_store_impl> store_;
	std::uint64_t const local_id_{};
	data_id const id_;
	std::uint64_t const plain_size_{};
	std::uint64_t const chunk_size_{};

	// guards the decryptor order and the cache
	mutable std::mutex mutex_;
	// never empty
	std::vector<data_decryptor> decryptors_;
	// the last decrypted chunk: sequential reads in small pieces decrypt each chunk once
	std::optional<std::uint64_t> cached_no_;
	octet_vector cached_;
};

bool evict_data(record_data_store_impl& store, data_id const& id) {
	std::unique_lock lock{store.mutex};
	auto row = store.table.find(id);
	bool const ok = row && row->state != record_data_state::upload_pending;
	if(ok) {
		store.files.remove(id);
		row->have.clear();
		store.table.set_have(row->local_id, row->have);
		if(row->state != record_data_state::invalid) {
			store.table.set_state(row->local_id, record_data_state::removed);
		}
	}
	return ok;
}

void stored_record_data::remove_data() {
	std::unique_lock lock{mutex_};
	if(evict_data(*store_, id_)) {
		cached_no_.reset();
		cached_.clear();
	}
}

}

// -- data_writer --

data_writer::data_writer(std::shared_ptr<record_data_store_impl> store, encryption_key const& group_key, std::uint32_t chunk_size)
: store_(std::move(store))
, stage_(store_->files.begin_staging())
{
	try {
		// the staging area is this writer's alone: no lock
		encryptor_ = std::make_unique<data_encryptor>(group_key, chunk_size,
			[store = store_, stage = stage_](std::uint64_t chunk_no, octet_vector const& encrypted) {
				store->files.write_staged(stage, chunk_no, encrypted);
			});
	} catch(...) {
		store_->files.discard_staging(stage_);
		throw;
	}
}

data_writer::data_writer(data_writer&&) noexcept = default;

data_writer::~data_writer() {
	if(encryptor_) {
		try {
			store_->files.discard_staging(stage_);
		} catch(std::exception const& e) {
			LOG_WARN("failed to discard record data staging: {}", e.what());
		}
	}
}

void data_writer::write(octet_span plain) {
	if(!encryptor_) {
		throw make_error(securepath::errc::invalid_state, "record data writer already finished");
	}
	encryptor_->write(plain);
}

encrypted_data_result data_writer::finish() {
	if(!encryptor_) {
		throw make_error(securepath::errc::invalid_state, "record data writer already finished");
	}
	auto result = encryptor_->finish();
	store_->register_created(stage_, result);
	encryptor_.reset();
	return result;
}

void copy_record_data(record_data& source, data_writer& writer) {
	std::uint64_t const size = source.size();
	octet_vector piece(static_cast<std::size_t>(std::min<std::uint64_t>(size, 256 * 1024)));
	std::uint64_t pos = 0;
	while(pos < size) {
		std::uint64_t const n = source.read(pos, piece.data(), std::min<std::uint64_t>(piece.size(), size - pos));
		if(n == 0) {
			throw make_error(securepath::errc::invalid_data, "record data source ended before its size");
		}
		writer.write(octet_span{piece}.first(static_cast<std::size_t>(n)));
		pos += n;
	}
}

// -- record_data_store --

record_data_store::record_data_store(database::connection_ptr db, std::filesystem::path data_root)
: impl_(std::make_shared<record_data_store_impl>(std::move(db), std::move(data_root)))
{
}

data_writer record_data_store::create(encryption_key const& group_key, std::uint32_t chunk_size) {
	return data_writer{impl_, group_key, chunk_size};
}

record_data_handle record_data_store::open(std::vector<encryption_key> const& group_keys
	, data_descriptor const& descriptor, data_header const& header) {
	if(group_keys.empty()) {
		throw make_error(sync::errc::no_encryption_key_found, "no group key to open record data with");
	}
	record_data_handle ret;
	auto const local_id = impl_->table.ensure(descriptor);
	auto const row = impl_->table.find(local_id);
	if(row && row->descriptor == descriptor) {
		std::vector<data_decryptor> decryptors;
		for(auto const& key : group_keys) {
			decryptors.emplace_back(key, descriptor, header);
		}
		ret = std::make_shared<stored_record_data>(impl_, local_id, std::move(decryptors));
	} else {
		LOG_WARN("record data descriptor contradicts the known data [data_id={}]", to_hex(descriptor.manifest_digest));
	}
	return ret;
}

std::optional<data_state_row> record_data_store::find(data_id const& id) const {
	return impl_->table.find(id);
}

void record_data_store::set_state(data_id const& id, record_data_state state) {
	std::unique_lock lock{impl_->mutex};
	auto const row = impl_->table.find(id);
	if(row) {
		impl_->table.set_state(row->local_id, state);
	}
}

bool record_data_store::evict(data_id const& id) {
	return evict_data(*impl_, id);
}

std::size_t record_data_store::remove_unreferenced(std::function<bool(std::uint64_t)> const& is_referenced) {
	std::unique_lock lock{impl_->mutex};
	std::size_t removed = 0;
	for(auto const local_id : impl_->table.all_ids()) {
		if(!is_referenced(local_id)) {
			auto const row = impl_->table.find(local_id);
			if(row) {
				impl_->files.remove(row->descriptor.manifest_digest);
			}
			impl_->table.remove(local_id);
			++removed;
		}
	}
	return removed;
}

bool record_data_store::set_manifest(data_id const& id, data_manifest const& manifest) {
	std::unique_lock lock{impl_->mutex};
	auto const row = impl_->table.find(id);
	bool const ok = row && manifest.matches(row->descriptor);
	if(ok) {
		impl_->table.set_manifest(row->local_id, manifest);
	}
	return ok;
}

std::optional<data_state_row> record_data_store::register_data(data_descriptor const& descriptor, data_manifest const& manifest) {
	std::optional<data_state_row> ret;
	if(manifest.matches(descriptor)) {
		std::unique_lock lock{impl_->mutex};
		auto const local_id = impl_->table.ensure(descriptor);
		auto row = impl_->table.find(local_id);
		if(row && row->descriptor == descriptor) {
			impl_->table.set_manifest(local_id, manifest);
			ret = std::move(row);
		}
	}
	return ret;
}

std::optional<data_manifest> record_data_store::manifest(data_id const& id) const {
	std::optional<data_manifest> ret;
	auto const row = impl_->table.find(id);
	if(row) {
		ret = impl_->table.manifest(row->local_id);
	}
	return ret;
}

bool record_data_store::store_chunk(data_id const& id, std::uint64_t chunk_no, octet_span encrypted) {
	// the hashing stays outside the lock
	auto const known = manifest(id);
	bool ok = known && known->verify_chunk(chunk_no, encrypted);
	if(ok) {
		std::unique_lock lock{impl_->mutex};
		auto const row = impl_->table.find(id);
		ok = row.has_value();
		if(ok) {
			impl_->add_chunk(*row, chunk_no, encrypted);
		}
	}
	return ok;
}

std::optional<octet_vector> record_data_store::read_chunk(data_id const& id, std::uint64_t chunk_no) const {
	return impl_->read_chunk(id, chunk_no);
}

}
