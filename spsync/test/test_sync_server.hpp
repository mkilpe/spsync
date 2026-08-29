#pragma once

#include "test_progress.hpp"
#include "test_sync_engine.hpp"
#include "util.hpp"

#include <spsync/comm/interface.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/server/server_lib/chain_sync.hpp>

#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/private_data_cache.hpp>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <deque>
#include <functional>
#include <memory>

namespace securepath::sync::test {

class test_sync_server;

/**
 * Test client io
 */
class test_sync_server_client : public comm_input {
public:
	test_sync_server_client(database::connection_ptr);

	void set_output(comm_output&);
	void connect(test_sync_server& server);
	void disconnect();

	bool handle_events();

	/// Fetches current sequence number
	virtual request_handle fetch_sequence_number();

	/// Fetches records for specific range of sequence numbers [start, end]
	virtual request_handle fetch_records(sequence_number start, sequence_number end);

	/// Fetches record data for given record
	virtual request_handle fetch_data(sequence_number record);

	/// Tries to commit to a record and uploads the record data if committing was successful
	virtual request_handle commit_record(record_handle);

	/// Accessors to common, shared infrastructure
	virtual sync::progress& progress() const;
	virtual record_storage& records() const;

private:
	mutable test_progress progress_;
	mutable record_storage storage_;
	comm_output* output_{};
	test_sync_server* server_{};
	sequence_number last_pushed_record_;
	request_handle req_handle{};
	std::deque<std::function<void()>> events_;
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
	test_sync_server_client io{database};
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
	test_sync_server(chain_sync_config config = {});

public:
	database::connection_ptr database{create_test_database("test_sync_server.db")};
	chain_sync sync;
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

public:
	sync_mode mode;
	auth_mode amode;
	test_sync_server server;
	std::deque<std::unique_ptr<test_sync_server_client_context>> clients;
};

}

