#pragma once

#include <spsync/comm/transfer_config.hpp>
#include <spsync/core/data/data_encryptor.hpp>
#include <spsync/core/data/record_data_store.hpp>
#include <spsync/core/record_data.hpp>
#include <spsync/protocol/error.hpp>
#include <spsync/protocol/protocol_base.hpp>
#include <spsync/util/result.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

/**
 * What the tests of record data share, header only: made data in and out of a store,
 * a log of what a transfer queue reported, the error a result carries. The server
 * fixtures (servers, tickets, uploads over the wire) are in
 * server/server_lib/test/data_server_fixtures.hpp.
 */
namespace securepath::sync::test {

/// a group key like the one a storage has
inline encryption_key test_group_key(std::uint64_t seq = 3) {
	return encryption_key{sequence_number{seq}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
}

/// a descriptor with a random id; the defaults are small, not what a chain accepts
inline data_descriptor test_descriptor(std::uint64_t enc_size = 5080, std::uint32_t chunk_size = 1000) {
	return data_descriptor{enc_size, chunk_size, securepath::test::random_octet_vector(64)};
}

/// a fresh database and an empty chunk directory for a store
inline database::connection_ptr fresh_database(std::string const& name, std::filesystem::path const& root) {
	std::remove(name.c_str());
	std::filesystem::remove_all(root);
	return database::sqlite::create_sqlite_connection(name);
}

/// a data as a client made it, held nowhere: descriptor, manifest and the encrypted chunks
struct client_data {
	data_descriptor descriptor;
	data_manifest manifest;
	std::map<std::uint64_t, octet_vector> chunks;
};

inline client_data make_client_data(std::size_t size, std::uint32_t chunk_size = 1000) {
	client_data ret;
	data_encryptor enc(test_group_key(1), chunk_size, [&](std::uint64_t no, octet_vector const& c) { ret.chunks[no] = c; });
	enc.write(securepath::test::random_octet_vector(size));
	auto const result = enc.finish();
	ret.descriptor = result.descriptor;
	ret.manifest = result.manifest;
	return ret;
}

/// a data written into a store as the engine leaves it: all of it held, upload_pending
struct stored_data {
	encrypted_data_result result;
	octet_vector plain;
};

inline stored_data store_data(record_data_store& store, std::size_t size, std::uint32_t chunk_size = 1000
	, encryption_key const& key = test_group_key(1)) {
	stored_data ret;
	ret.plain = securepath::test::random_octet_vector(size);
	auto writer = store.create(key, chunk_size);
	writer.write(ret.plain);
	ret.result = writer.finish();
	return ret;
}

/// the plaintext of a data through its handle
inline octet_vector read_all(record_data& data) {
	octet_vector ret(data.size());
	ret.resize(data.read(0, ret.data(), ret.size()));
	return ret;
}

/// what a transfer queue (an uploader, a downloader) reported through its callbacks
struct transfer_log {
	struct report {
		data_id id;
		std::uint64_t transferred{};
		std::uint64_t total{};
	};

	transfer_done_callback done() {
		return [this](data_id const& id, std::optional<error> err) {
			std::unique_lock lock{mutex};
			finished.emplace_back(id, std::move(err));
			++count;
		};
	}

	transfer_progress_callback progress() {
		return [this](data_id const& id, std::uint64_t transferred, std::uint64_t total) {
			std::unique_lock lock{mutex};
			reports.push_back({id, transferred, total});
		};
	}

	std::size_t finished_count() const {
		std::unique_lock lock{mutex};
		return finished.size();
	}

	/// the transfer i ended with the given error
	bool ended_with(std::size_t i, protocol::errc code) const {
		std::unique_lock lock{mutex};
		return i < finished.size() && finished[i].second && finished[i].second->code() == make_error_code(code);
	}

	/// the progress reported for one data, in order
	std::vector<report> reports_of(data_id const& id) const {
		std::unique_lock lock{mutex};
		std::vector<report> ret;
		for(auto const& r : reports) {
			if(r.id == id) {
				ret.push_back(r);
			}
		}
		return ret;
	}

public:
	/// transfers ended, for the waits of a test
	std::atomic<std::size_t> count{0};
	mutable std::mutex mutex;
	std::vector<std::pair<data_id, std::optional<error>>> finished;
	std::vector<report> reports;
};

/// the error an error, a wire error, an optional error or a result carries is the given one
inline bool is_error(error const& err, protocol::errc code) {
	return err.code() == make_error_code(code);
}

inline bool is_error(network::net_error const& err, protocol::errc code) {
	return is_error(protocol::to_error(err), code);
}

inline bool is_error(std::optional<error> const& err, protocol::errc code) {
	return err && is_error(*err, code);
}

template<typename T>
bool is_error(util::result<T> const& r, protocol::errc code) {
	return !r && is_error(r.get_error(), code);
}

}
