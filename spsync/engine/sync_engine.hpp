#pragma once

#include "history_verifier.hpp"
#include "interface.hpp"
#include "sync_engine_config.hpp"
#include <spsync/comm/interface.hpp>
#include <spsync/core/crypto_context.hpp>
#include <spsync/core/progress.hpp>

#include <memory>

namespace securepath::sync {

class encryption_key_storage;


/**
 * The engine to synchronise records and record data
 */
class sync_engine
	: public comm_output
	, public engine_input
{
public:
	sync_engine(event_system::event_loop&, comm_input&, crypto_context&, sync_engine_config);
	~sync_engine();

	/// set the engine output interface that it uses to communicate with higher layer
	void set_output(engine_output*);

	/// re-set the engine configuration
	void set_config(sync_engine_config);

	// --- comm_output interface, see comm/interface.hpp ---
	virtual void on_connected();
	virtual void on_disconnected(std::optional<error>);
	virtual void on_sequence_number_response(request_handle, result<sequence_info> const&);
	virtual void on_record_response(request_handle, record_response const&);
	virtual void on_data_downloaded(request_handle, std::optional<error>);
	virtual void on_data_available(data_id, bool complete);
	virtual void on_commit_response(request_handle, commit_response const&);
	virtual void on_data_uploaded(request_handle, std::optional<error>);
	virtual void on_record_received(chain_block const&, std::optional<block_envelope> const& = {});

	// --- engine_input interface, see interface.hpp ---
	virtual record_handle sync_object_change(object_id, metadata, record_data_handle = {});
	virtual record_data_handle object_data(record_handle, std::size_t change = 0);
	virtual record_data_handle fetch_object_data(record_handle, std::size_t change = 0);
	virtual record_handle sync_user_change(plain_user_change_data change_data, metadata = {});
	virtual record_handle sync_segment_end(metadata = {});

	/// verify the stored in sync history (segments plan SEG 4), strategy from the config
	util::result<history_verify_report> verify_history() const;

	/**
	 * Prune the local history before the given committed segment record (segments plan
	 * SEG 6), keeping the records current objects depend on; the server keeps the full
	 * history. An empty tag prunes at the newest segment. Returns the anchor block hash:
	 * it becomes the trusted anchor for this session and the caller must persist it into
	 * sync_engine_config::trusted_anchor for later sessions, so a reload verifies from
	 * the anchor.
	 */
	octet_vector prune_history(record_tag const& segment_tag = {});
private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}

