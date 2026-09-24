#include "record_data_store.hpp"
#include "chunk_files.hpp"
#include "data_decryptor.hpp"

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>
#include <securepath/util/error.hpp>

#include <algorithm>
#include <cstring>
#include <atomic>
#include <mutex>
#include <utility>

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
				drop_if_lost(*row, chunk_no);
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

	/**
	 * The staged chunks of a whole data - a writer's (upload_pending), or rebuilt from
	 * held content (in_sync, in place of whatever part of it was held) - become the data.
	 * The row first: a crash in between leaves an unreferenced row for remove, never chunk
	 * files nothing knows of; the row says what is held only once the files are there.
	 */
	void register_held(std::string const& stage, encrypted_data_result const& result, record_data_state state, bool replace) {
		std::unique_lock lock{mutex};
		auto const& id = result.descriptor.manifest_digest;
		std::uint64_t local_id{};
		{
			auto tact = table.transaction();
			local_id = table.ensure(result.descriptor);
			table.set_manifest(local_id, result.manifest);
			table.set_header(local_id, result.header);
		}
		if(replace) {
			files.remove(id);
		}
		files.commit_staging(stage, id);
		{
			auto tact = table.transaction();
			have_bitmap have{result.descriptor.chunk_count()};
			have.set_all();
			table.set_have(local_id, have);
			table.set_state(local_id, state);
		}
	}

	/// keep a chunk that verified against the manifest
	void add_chunk(data_state_row row, std::uint64_t chunk_no, octet_span encrypted) {
		if(!row.have.test(chunk_no)) {
			files.write(row.descriptor.manifest_digest, chunk_no, encrypted);
			mark_held(row, chunk_no);
		}
	}

	/// a chunk received in pieces verified against the manifest: its staged file becomes the chunk
	bool adopt_chunk(data_id const& id, std::uint64_t chunk_no, std::string const& stage) {
		std::unique_lock lock{mutex};
		auto row = table.find(id);
		bool const known = row.has_value();
		if(known && !row->have.test(chunk_no)) {
			files.adopt_staged_chunk(stage, chunk_no, id);
			mark_held(*row, chunk_no);
		} else {
			// held already, or the data went meanwhile
			files.discard_staging(stage);
		}
		return known;
	}

	/// a piece of a held chunk; a chunk the bitmap promises but the disk lost is dropped.
	/// The range is the asker's - over the wire, anybody's: one outside the chunk is
	/// refused and says nothing about the chunk
	std::optional<octet_vector> read_piece(data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, std::size_t size) {
		std::unique_lock lock{mutex};
		std::optional<octet_vector> ret;
		auto row = table.find(id);
		if(row && row->have.test(chunk_no) && row->descriptor.chunk_holds_range(chunk_no, offset, size)) {
			ret = files.read_piece(id, chunk_no, offset, size);
			if(!ret) {
				drop_if_lost(*row, chunk_no);
			}
		}
		return ret;
	}

private:
	// requires the mutex
	void mark_held(data_state_row& row, std::uint64_t chunk_no) {
		row.have.set(chunk_no);
		table.set_have(row.local_id, row.have);
		if(row.have.complete() && row.state != record_data_state::upload_pending) {
			table.set_state(row.local_id, record_data_state::in_sync);
		}
	}

	/**
	 * A held chunk could not be read. Lost is a file that is not there or shorter than
	 * the descriptor says: that chunk is dropped to be fetched again. A file of the right
	 * size that does not open or read is trouble of the moment (descriptors, the disk),
	 * and dropping it would throw a good chunk - maybe the only copy - away. Requires the
	 * mutex.
	 */
	void drop_if_lost(data_state_row& row, std::uint64_t chunk_no) {
		auto const& id = row.descriptor.manifest_digest;
		auto const on_disk = files.size(id, chunk_no);
		if(!on_disk || *on_disk < row.descriptor.chunk_enc_size(chunk_no)) {
			LOG_WARN("record data chunk lost [data_id={}, chunk={}]", to_hex(id), chunk_no);
			drop_chunk(row, chunk_no);
		} else {
			LOG_WARN("record data chunk could not be read, kept [data_id={}, chunk={}]", to_hex(id), chunk_no);
		}
	}

	// requires the mutex
	void drop_chunk(data_state_row& row, std::uint64_t chunk_no) {
		++drops;
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
	/// counts the times held chunks went (eviction, prune, a lost chunk): a handle's cached
	/// chunk is good for as long as this stands still
	std::atomic<std::uint64_t> drops{0};
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
		auto const row = store_->table.find(id_);
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

	// the row is addressed by the data id: the handle may outlive its row (a rollback,
	// a sweep), and whatever comes after it is not this data
	record_data_state state() const override {
		auto const row = store_->table.find(id_);
		return row ? row->state : record_data_state::invalid;
	}

	void set_state(record_data_state state) override {
		if(auto const row = store_->table.find(id_)) {
			store_->table.set_state(row->local_id, state);
		}
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
		// chunks went since the chunk was cached (an eviction, a prune, a lost chunk - by
		// anybody): the cache is not what is held any more
		auto const drops = store_->drops.load();
		if(drops != cached_at_drops_) {
			cached_no_.reset();
			cached_.clear();
			cached_at_drops_ = drops;
		}
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
	/// record_data_store_impl::drops when the cache was last known good
	std::uint64_t cached_at_drops_{};
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

/// the local chunks of a data go, the row and the manifest stay; the caller holds the lock
void drop_chunks(record_data_store_impl& store, data_state_row& row, record_data_state state) {
	++store.drops;
	store.files.remove(row.descriptor.manifest_digest);
	row.have.clear();
	store.table.set_have(row.local_id, row.have);
	store.table.set_state(row.local_id, state);
}

bool evict_data(record_data_store_impl& store, data_id const& id) {
	std::unique_lock lock{store.mutex};
	auto row = store.table.find(id);
	bool const ok = row && row->state != record_data_state::upload_pending;
	if(ok) {
		// removed is what a held data becomes; what was never held, is wanted, invalid or
		// pruned stays that - the tombstone of a prune and a download that is on its way
		// are not the eviction's to undo
		bool const held = row->state == record_data_state::in_sync || row->state == record_data_state::removed;
		drop_chunks(store, *row, held ? record_data_state::removed : row->state);
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
	store_->register_held(stage_, result, record_data_state::upload_pending, false);
	encryptor_.reset();
	return result;
}

// -- incoming_chunk --

incoming_chunk::incoming_chunk(std::shared_ptr<record_data_store_impl> store, data_id id, std::uint64_t chunk_no
	, std::uint64_t expected_size, octet_vector expected_digest)
: store_(std::move(store))
, id_(std::move(id))
, chunk_no_(chunk_no)
, expected_size_(expected_size)
, expected_digest_(std::move(expected_digest))
, stage_(store_->files.begin_staging())
, open_(true)
{
}

incoming_chunk::incoming_chunk(incoming_chunk&& other) noexcept
: store_(std::move(other.store_))
, id_(std::move(other.id_))
, chunk_no_(other.chunk_no_)
, expected_size_(other.expected_size_)
, expected_digest_(std::move(other.expected_digest_))
, stage_(std::move(other.stage_))
, hash_(std::move(other.hash_))
, received_(other.received_)
, open_(std::exchange(other.open_, false))
{
}

incoming_chunk::~incoming_chunk() {
	discard();
}

void incoming_chunk::discard() {
	if(open_) {
		open_ = false;
		try {
			store_->files.discard_staging(stage_);
		} catch(std::exception const& e) {
			LOG_WARN("failed to discard an incoming chunk: {}", e.what());
		}
	}
}

bool incoming_chunk::append(std::uint64_t offset, octet_span piece) {
	bool const ok = open_ && offset == received_ && !piece.empty() && piece.size() <= expected_size_ - received_;
	if(ok) {
		// the staging area is this chunk's alone: no lock
		try {
			store_->files.append_staged(stage_, chunk_no_, piece);
		} catch(...) {
			// a part of the piece may be in the file: the chunk starts over, a piece sent
			// again must not land behind it
			discard();
			throw;
		}
		hash_.update(piece);
		received_ += piece.size();
	} else {
		discard();
	}
	return ok;
}

bool incoming_chunk::finish() {
	// the digest is of the pieces as they came, the file is what is kept: it has to be
	// all of them and nothing else
	bool ok = open_ && complete() && hash_.final() == expected_digest_
		&& store_->files.staged_size(stage_, chunk_no_) == expected_size_;
	if(ok) {
		open_ = false;
		ok = store_->adopt_chunk(id_, chunk_no_, stage_);
	} else {
		discard();
	}
	return ok;
}

namespace {

/// a whole source in pieces, never more than one piece in memory
void stream_record_data(record_data& source, std::function<void(octet_span)> const& write) {
	std::uint64_t const size = source.size();
	octet_vector piece(static_cast<std::size_t>(std::min<std::uint64_t>(size, 256 * 1024)));
	std::uint64_t pos = 0;
	while(pos < size) {
		std::uint64_t const n = source.read(pos, piece.data(), std::min<std::uint64_t>(piece.size(), size - pos));
		if(n == 0) {
			throw make_error(securepath::errc::invalid_data, "record data source ended before its size");
		}
		write(octet_span{piece}.first(static_cast<std::size_t>(n)));
		pos += n;
	}
}

}

void copy_record_data(record_data& source, data_writer& writer) {
	stream_record_data(source, [&](octet_span piece) { writer.write(piece); });
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
	if(!usable_data_descriptor(descriptor)) {
		LOG_WARN("record data descriptor out of bounds [data_id={}]", to_hex(descriptor.manifest_digest));
		return ret;
	}
	auto const local_id = impl_->table.ensure(descriptor);
	auto const row = impl_->table.find(local_id);
	if(row && row->descriptor == descriptor) {
		if(!impl_->table.header(local_id)) {
			// the content index learns of the data the first time its header is seen
			impl_->table.set_header(local_id, header);
		}
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

std::optional<held_content> record_data_store::find_content(octet_vector const& content_digest, data_id const& other_than) const {
	std::optional<held_content> ret;
	for(auto const& row : impl_->table.find_by_content(content_digest)) {
		auto header = impl_->table.header(row.local_id);
		bool const usable = !ret && header && row.have.complete() && row.descriptor.manifest_digest != other_than
			&& row.state != record_data_state::invalid;
		if(usable) {
			ret = held_content{row.descriptor, std::move(*header)};
		}
	}
	return ret;
}

bool record_data_store::adopt_content(record_data& source, encryption_key const& group_key, data_descriptor const& wanted
	, data_header const& wanted_header) {
	bool ok = source.size() == wanted_header.plain_size && wanted.chunk_size != 0;
	if(ok) {
		auto const stage = impl_->files.begin_staging();
		try {
			data_encryptor encryptor(group_key, wanted.chunk_size, [&](std::uint64_t chunk_no, octet_vector const& encrypted) {
				impl_->files.write_staged(stage, chunk_no, encrypted);
			}, wanted_header.nonce);
			stream_record_data(source, [&](octet_span piece) { encryptor.write(piece); });
			auto const result = encryptor.finish();
			// the same chunks only when the key and the content are the wanted data's
			ok = result.descriptor == wanted && result.header.content_digest == wanted_header.content_digest;
			if(ok) {
				impl_->register_held(stage, result, record_data_state::in_sync, true);
			} else {
				impl_->files.discard_staging(stage);
			}
		} catch(...) {
			impl_->files.discard_staging(stage);
			throw;
		}
	}
	return ok;
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

bool record_data_store::prune(data_id const& id) {
	std::unique_lock lock{impl_->mutex};
	auto row = impl_->table.find(id);
	if(row) {
		drop_chunks(*impl_, *row, record_data_state::pruned);
	}
	return row.has_value();
}

std::size_t record_data_store::remove(std::vector<data_id> const& ids) {
	std::unique_lock lock{impl_->mutex};
	std::size_t removed = 0;
	for(auto const& id : ids) {
		auto const row = impl_->table.find(id);
		if(row) {
			++impl_->drops;
			impl_->files.remove(id);
			impl_->table.remove(row->local_id);
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
	if(usable_data_descriptor(descriptor) && manifest.matches(descriptor)) {
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

std::optional<data_state_row> record_data_store::register_data(data_descriptor const& descriptor) {
	std::optional<data_state_row> row;
	if(usable_data_descriptor(descriptor)) {
		std::unique_lock lock{impl_->mutex};
		row = impl_->table.find(impl_->table.ensure(descriptor));
		if(row && row->descriptor != descriptor) {
			row.reset();
		}
	}
	return row;
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

std::optional<incoming_chunk> record_data_store::begin_chunk(data_id const& id, std::uint64_t chunk_no) {
	std::optional<incoming_chunk> ret;
	auto const row = impl_->table.find(id);
	// the one digest of the manifest this chunk is checked against: the whole manifest
	// may name max_data_chunks of them, it is not decoded per chunk
	auto const digest = row && chunk_no < row->descriptor.chunk_count() ? impl_->table.chunk_digest(row->local_id, chunk_no) : std::nullopt;
	if(digest) {
		ret.emplace(impl_, id, chunk_no, row->descriptor.chunk_enc_size(chunk_no), *digest);
	}
	return ret;
}

bool record_data_store::has_manifest(data_id const& id) const {
	auto const row = impl_->table.find(id);
	return row && impl_->table.has_manifest(row->local_id);
}

std::optional<octet_vector> record_data_store::read_chunk(data_id const& id, std::uint64_t chunk_no) const {
	return impl_->read_chunk(id, chunk_no);
}

std::optional<octet_vector> record_data_store::read_chunk_piece(data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, std::size_t size) const {
	return impl_->read_piece(id, chunk_no, offset, size);
}

}
