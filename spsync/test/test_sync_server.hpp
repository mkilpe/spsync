#ifndef SPSYNC_TEST_TEST_SYNC_SERVER_HEADER
#define SPSYNC_TEST_TEST_SYNC_SERVER_HEADER

#include "test_progress.hpp"
#include "test_sync_engine.hpp"
#include "util.hpp"

#include <spsync/comm/interface.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/server/server_lib/chain_sync.hpp>

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

	void handle_events();

	/// Fetches current sequence number
	virtual request_handle fetch_sequence_number();

	/// Fetches records for specific range of sequence numbers [start, end]
	virtual request_handle fetch_records(sequence_number start, sequence_number end);

	/// Fetches record data for given record
	virtual request_handle fetch_data(sequence_number record);

	/// Tries to commit to a record and uploads the record data if committing was successful
	virtual request_handle commit_record(record_handle);

	/// Accessors to common, shared infrastructure
	virtual sync::progress& progress();
	virtual record_storage& records();

private:
	test_progress progress_;
	record_storage storage_;
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
	test_sync_server_client_context();

	database::connection_ptr database{create_test_database("test_sync_server_client.db")};
	test_sync_server_client io{database};
	encryption_key_storage enc_keys{database};
	sync_engine_config engine_config;
	test_sync_engine engine{io, enc_keys, engine_config};
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

	/// add client and by default connect to the test server
	void add_client(bool connect = true);


	/// handle events for all clients
	void handle_events();

public:
	test_sync_server server;
	std::deque<std::unique_ptr<test_sync_server_client_context>> clients;
};

}

#endif