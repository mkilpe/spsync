#pragma once

#include "record_verifier.hpp"
#include "sync_engine_config.hpp"

#include <spsync/comm/interface.hpp>
#include <spsync/core/crypto_context.hpp>
#include <spsync/core/data/record_data_store.hpp>
#include <spsync/core/record_data.hpp>
#include <spsync/core/record_storage.hpp>

#include <functional>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace securepath::sync {

/**
 * The record data half of the engine (record_data.txt RD7): what the storage owes and
 * wants once its records moved - the uploads of confirmed records' data in commit
 * order, the fetch policy (RD6) and the downloads, their answers, held content
 * adopted instead of downloaded (RDS 6), the retention policy at a history cut (RD9)
 * and the sweep of data no record names. Works on the record storage, the data
 * store and comm, and reports through the two callbacks. The engine calls it under
 * its mutex - adopt is the exception, it encrypts and is called without - so nothing
 * here locks. What the server refused during a connection is remembered until the
 * next one.
 */
class data_sync {
public:
	/// a change of a data change record, decrypted; nullopt when the record cannot be read
	using change = data_change_record_verifier::single_data;
	using read_change_result = std::optional<change>;

	struct events {
		/// a data of the store changed state (the transfers' ends, the policy)
		std::function<void(data_id const&, record_data_state)> state_changed;
		/// a transfer ended with an error, or the server let the data go
		std::function<void(data_id const&, error const&)> transfer_failed;
	};

	/// what it takes to make a wanted data out of held content instead of downloading it
	struct adoption {
		/// the held data with the same content
		record_data_handle source;
		/// the group keys the wanted data may be encrypted with (D9 candidates)
		std::vector<encryption_key> keys;
		data_descriptor wanted;
		data_header header;
	};

	/// config gives the log id and the fetch policy; it is the engine's, re-set there
	data_sync(comm_input&, crypto_context&, record_storage&, record_data_store&, sync_engine_config const&, events);

	/// the connection is up: nothing is on its way, what was refused may be asked again
	void on_connected();

	/// the connection went: the answers to what is on its way never come
	void on_disconnected();

	/// every transfer the storage owes or wants, after anything that may have changed that
	void request_transfers();

	void on_upload_answer(request_handle, std::optional<error> const&);
	void on_download_answer(request_handle, std::optional<error> const&);

	/// the server tells a data server holds the data now: what waited for it goes on
	void on_data_announced(data_id const&);

	/// a source streamed into the store, encrypted with the key and cut into chunks; the
	/// caller finishes the writer together with the record naming the data
	data_writer stream(encryption_key const&, std::uint32_t chunk_size, record_data& source);

	/**
	 * The retention policy of the storage at a local history cut (RD9,
	 * storage_limits::kept_data_versions, learned from the server): the data of the
	 * versions of an object beyond the newest kept ones below the anchor goes, the
	 * records stay. A data still to be uploaded is left alone - it may be the only copy,
	 * the server says when it does not want it any more - and so is one that is being
	 * fetched: somebody asked for it, and the chunks still arriving would land in a
	 * pruned row.
	 */
	void prune_superseded(sequence_number anchor, std::uint32_t kept_versions);

	/// drop the data no stored record references any more (RD9): records went with a
	/// truncation or a history cut, or a record could not be created for its data
	void sweep();

	/// the record data of a change, null when there is none or it cannot be read
	record_data_handle open_change_data(change const&) const;

	/**
	 * RDS 6: the content of the change's data is held under another data id (the same
	 * file sent again, by anybody) and the data itself is not: it can be rebuilt locally.
	 */
	std::optional<adoption> plan_adoption(read_change_result const&) const;

	/// encrypts the whole content again: call without the engine mutex. False = download it
	bool adopt(adoption const&) const;

	/// open_change_data, and the data fetched when it is not held
	record_data_handle fetch_change_data(read_change_result const&);

private:
	template<typename Ask>
	void request_transfers_of(record_data_state, std::map<request_handle, data_id>& on_their_way
		, std::set<data_id> const& refused, char const* what, Ask ask);
	void request_uploads();
	void request_downloads();
	void mark_auto_fetch();
	void set_state(data_id const&, record_data_state);
	void mark_uploaded(data_id const&);
	void on_data_pruned(data_id const&, error const&);
	void on_download_failed(data_id const&, std::optional<error> const&);
	bool want_data(data_id const&);

private:
	comm_input& comm_;
	crypto_context& crypto_;
	record_storage& records_;
	record_data_store& store_;
	sync_engine_config const& config_;
	events events_;
	/// the data uploads asked from comm without an answer yet, by request handle
	std::map<request_handle, data_id> uploads_;
	/// data whose upload failed during this connection; tried again after the next connect
	std::set<data_id> failed_uploads_;
	/// the same for the downloads; a failed one is also tried when it is asked for again
	std::map<request_handle, data_id> downloads_;
	std::set<data_id> failed_downloads_;
};

}
