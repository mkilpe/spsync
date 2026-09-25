#pragma once

#include <spsync/core/data/record_data_store.hpp>

#include <filesystem>
#include <map>

#include "test_progress.hpp"
#include "test_sync_engine.hpp"
#include "util.hpp"

#include <spsync/comm/interface.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/server/server_lib/chain_sync.hpp>

#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/private_data_cache.hpp>

#include <set>
#include <utility>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <deque>
#include <functional>
#include <memory>
#include <spsync/util/move_only_function.hpp>

namespace securepath::sync::test {

class test_sync_server;

/**
 * Test client io
 */
class test_sync_server_client : public comm_input {
public:
	/// data_root: the chunk directory of the client's record data store, emptied first
	test_sync_server_client(database::connection_ptr, std::filesystem::path data_root);

	void set_output(comm_output&);
	void connect(test_sync_server& server);
	void disconnect();

	bool handle_events();

	/// Fetches current sequence number
	virtual request_handle fetch_sequence_number();

	/// Fetches records for specific range of sequence numbers [start, end]
	virtual request_handle fetch_records(sequence_number start, sequence_number end);

	/// copies the data out of the test server's holdings into this client's store
	virtual request_handle fetch_data(data_id const&);

	/// Tries to commit to a record and uploads the record data if committing was successful
	virtual request_handle commit_record(record_handle);

	/// the data servers of this harness take everything: the data goes into the test
	/// server's holdings, answered with success while connected
	virtual request_handle upload_data(data_id const&);

	/// Accessors to common, shared infrastructure
	virtual sync::progress& progress() const;
	virtual record_storage& records() const;
	virtual record_data_store* data() const { return &data_store_; }

	/// every upload_data call so far, in order
	std::vector<data_id> const& upload_requests() const { return upload_requests_; }

	/// every fetch_data call so far, in order
	std::vector<data_id> const& fetch_requests() const { return fetch_requests_; }

	/// number of requests the engine issued through this client (sequence/fetch/commit)
	std::uint64_t request_count() const { return req_handle; }

	/// the server this client is connected to; null when disconnected
	test_sync_server* connected_server() const { return server_; }

private:
	mutable test_progress progress_;
	mutable record_storage storage_;
	mutable record_data_store data_store_;
	std::vector<data_id> upload_requests_;
	std::vector<data_id> fetch_requests_;
	std::size_t seen_announcements_{};
	comm_output* output_{};
	test_sync_server* server_{};
	sequence_number last_pushed_record_;
	request_handle req_handle{};
	std::deque<move_only_function<void()>> events_;
};

/**
 * Test client context
 */
class test_sync_server_client_context {
public:
	test_sync_server_client_context(int n, sync_mode mode, auth_mode = auth_mode::only_tag);

	crypto::private_key user_key{crypto::generate_private_key()};
	util::user_id user{user_key.id()};

	event_system::single_thread_event_loop single_thread_event_loop;
	database::connection_ptr database;
	test_sync_server_client io;
	encryption_key_storage enc_keys{database};
	crypto::public_key_cache pkeys;
	crypto::private_data_cache pdata;
	crypto_context cc{pkeys, pdata, enc_keys, io.records()};
	sync_engine_config engine_config;
	test_sync_engine engine{single_thread_event_loop, io, cc, engine_config};
};


/**
 * The test implementation of sync server for unit tests (only single storage)
 */
class test_sync_server {
public:
	test_sync_server(chain_sync_config config = {}, std::string const& db_name = "test_sync_server.db");

public:
	database::connection_ptr database;
	chain_sync sync;
	/// identity reported to the clients (plan 4.5); every test server has its own
	crypto::public_key_id id;
	/// the validity limits reported with the sequence answer (RDS 8); 0 = not reported
	storage_limits limits;

	/// a data as the data servers of this harness hold it: ciphertext only
	struct held_data {
		data_manifest manifest;
		std::vector<octet_vector> chunks;
	};
	/// what the clients uploaded
	std::map<data_id, held_data> holdings;
	/// the data that became complete, in order: the clients hear of it as notify_data
	std::vector<data_id> announced;
};

/**
 * Test context for using the test_sync_server
 */
struct test_sync_context {
	test_sync_context(chain_sync_config config = {});

	/// add 'num' clients and by default connect to the test server
	void add_client(bool connect = true, int num = 1);

	/// return nth client
	test_sync_server_client_context& client(int num);

	/// connect nth client
	void connect_client(int n);

	/// disconnect nth client
	void disconnect_client(int n);

	/// handle events for all clients
	bool handle_events();

	/// create initial record using the first client as owner and add other clients as members
	void create_initial_record();

	/**
	 * The commit storm: every client commits records_per_client data changes round robin
	 * interleaved without waiting for responses; when special_mid_storm is set the first
	 * client also commits a user change halfway through. Handles events until quiet.
	 */
	void commit_storm(int records_per_client, bool special_mid_storm = false);

	/// returns true if all client and server record storages have same in sync records and given sequence number as last sequence (or the given seq is invalid)
	bool compare_record_storages(sequence_number = {}) const;

	// -- the multi server side (plan 4.7) --

	/// add a replica server; returns its index (0 is the primary `server`)
	std::size_t add_server(std::string const& db_name);

	/// server by index, 0 is the primary
	test_sync_server& server_n(std::size_t);
	test_sync_server const& server_n(std::size_t) const;
	std::size_t server_count() const;

	/// declare a replication link between two servers; delay = replication ticks a
	/// record waits before crossing
	void add_link(std::size_t a, std::size_t b, int delay = 0);

	/// take a link up or down (a partition); healing rescans, nothing is lost
	void set_link(std::size_t a, std::size_t b, bool up);

	/// connect the nth client to a specific server replica
	void connect_client_to(int n, std::size_t server_index);

	/**
	 * One deterministic replication exchange over every up link: the in-process stand-in
	 * for the 4.2 commit push and 4.4 anti-entropy (records cross via commit_foreign,
	 * idempotent). Returns true when a record moved. handle_events() ticks this too.
	 */
	bool replicate_tick();

	/**
	 * The multi server convergence check (plan 4.7): local sequences may differ between
	 * replicas, so the storages are compared semantically - the same operation id set,
	 * the same D9-derived membership and the same decrypted data change set everywhere.
	 * Decryption uses the first client's keys.
	 */
	bool servers_converged() const;

	/**
	 * Simplified run narration to stdout (catch shows it with -s and for failed cases):
	 * per server every locally committed and every replicated record as it lands, the
	 * link changes, and print_summary() for the final situation.
	 */
	void set_trace(bool enabled) { trace_ = enabled; }

	/// print the per-server end state: record/op counts, derived members, messages
	void print_summary() const;

public:
	sync_mode mode;
	auth_mode amode;
	test_sync_server server;
	std::deque<std::unique_ptr<test_sync_server_client_context>> clients;

	struct link_direction {
		/// tags already queued or delivered through this direction
		std::set<octet_vector> seen;
		/// countdown + record waiting to cross
		std::deque<std::pair<int, chain_block>> queue;
		/// the source chain is scanned up to here (it only grows: append-only log)
		sequence_number scanned;
	};
	struct replication_link {
		std::size_t a{}, b{};
		bool up{true};
		int delay{0};
		link_direction ab, ba;
	};
	std::deque<std::unique_ptr<test_sync_server>> extra_servers;
	std::deque<replication_link> links;

private:
	bool pump_link(replication_link&, bool ab_direction);
	void trace_progress();

	bool trace_{};
	/// per server: the head already narrated
	std::map<std::size_t, sequence_number> traced_;
	/// (server, tag) -> the server a replicated record came from
	std::map<std::pair<std::size_t, octet_vector>, std::size_t> replicated_from_;
};

}

