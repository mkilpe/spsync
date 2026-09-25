// SPDX-License-Identifier: MIT

#pragma once

#include "comm_test_interface.hpp"
#include "test_progress.hpp"
#include "test_sync_engine.hpp"
#include "util.hpp"

#include <spsync/client/record_util.hpp>
#include <spsync/core/data/record_data_store.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/private_data_cache.hpp>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <atomic>
#include <filesystem>
#include <string>

namespace securepath::sync::test {

class engine_context {
public:

	explicit engine_context(sync_engine_config config = {})
	: engine_config(std::move(config))
	{
		// own public key must be in the public key access for sync engine
		pkeys.insert(root_user_key.public_key());
		pdata.set_my_private_key(root_user_key);
		io.set_output(engine);
	}

	void create_initial_record() {
		// set initial key, use hard coded one for testing
		enc_keys.insert(encryption_key{sequence_number{1}, to_octet_vector("12345678901234567890123456789012")});
		users initial;
		initial.add(util::user_access{root_user, util::access_type::user_management_access});
		engine.sync_user_change(encrypt_last_key_for_users(initial, cc));
	}

	void add_default_commit_response() {
		io.add_commit_record_response([&](record_handle h)
			{
				auto record = h->record();
				record.set_sequence_and_parent_hash(io.next_sequence_number(), io.previous_block_hash());
				return record;
			});
	}

	static std::filesystem::path fresh_data_root() {
		static std::atomic<int> counter{0};
		std::filesystem::path root = "engine_test_data_" + std::to_string(counter++);
		std::filesystem::remove_all(root);
		return root;
	}

	crypto::private_key root_user_key{crypto::generate_private_key()};
	util::user_id root_user{root_user_key.id()};

	event_system::single_thread_event_loop single_thread_event_loop;
	database::connection_ptr database{create_test_database()};
	test_progress progress;
	record_storage storage{database};
	/// every context gets its own, empty chunk directory
	std::filesystem::path data_root{fresh_data_root()};
	record_data_store data_store{database, data_root};
	comm_test_interface io{progress, storage, &data_store};
	encryption_key_storage enc_keys{database};
	crypto::public_key_cache pkeys;
	crypto::private_data_cache pdata;
	crypto_context cc{pkeys, pdata, enc_keys, io.records()};
	sync_engine_config engine_config;
	test_sync_engine engine{single_thread_event_loop, io, cc, engine_config};
};

}

