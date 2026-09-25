// SPDX-License-Identifier: MIT

#pragma once

#include "file.hpp"
#include "object_store.hpp"

#include <spsync/client/record_data.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/record_storage.hpp>

#include <deque>
#include <optional>

namespace securepath::groupchat {

/// what the store keeps of a share: the record's entry and where it came from
struct stored_file {
	file_data data;
	user_id sharer;
	sync::record_internal_id iid{};
	sync::sequence_number seq;
	/// the data id (manifest digest) of the file's data: what the data events name
	octet_vector data_id;
	time_point receiver_time;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> s(ar);
		s & data & sharer & iid & seq & data_id & receiver_time;
	}
};

/**
 * The shared files of one chat over an object_store (shared_files.txt): confirmed shares
 * in arrival order, own pending ones after them. The transfer state is not kept here,
 * the channel reads it off the data (SF-D7). Not thread-safe.
 */
class file_storage {
public:
	/// a file as stored, with its place in the list
	struct row {
		file_id id;
		stored_file file;
		index_type index{};
		bool pending{};
	};

	explicit file_storage(database::connection_ptr);

	/// insert a share; a confirmed one leaves the pending list when it was there
	file_change insert(file_id const&, stored_file const&, bool pending);

	/// the files a search names, in its order
	std::deque<row> get(file_search) const;

	/// the file by id
	std::optional<row> find(file_id const&) const;

	/// the file whose data the id names
	std::optional<file_id> find_by_data(octet_vector const& data_id) const;

	/// the newest confirmed record sequence held: where the reconciliation starts
	sync::sequence_number latest_sequence() const;

	/// drop a pending share (the record was rejected for good); false when not pending
	bool remove_pending(file_id const&);

private:
	object_store store_;
	database::connection_ptr db_;
};

/// the share a change carries, when it is one: the gc_file_v1 entry with the data descriptor
std::optional<stored_file> file_of(sync::single_data_change const&);

/// bring the file list up to date with the records (start-up)
void sync_file_storage(file_storage&, sync::record_storage const&, sync::encryption_key_storage const&);

}
