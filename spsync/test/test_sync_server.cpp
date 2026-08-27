#include "test_sync_server.hpp"
#include <spsync/client/record_util.hpp>

namespace securepath::sync::test {

test_sync_server_client::test_sync_server_client(database::connection_ptr db)
: storage_(db)
{
}

void test_sync_server_client::set_output(comm_output& out) {
	output_ = &out;
}

void test_sync_server_client::connect(test_sync_server& server) {
	LOG_INFO("Client connected");
	server_ = &server;
	last_pushed_record_ = server_->sync.current_sequence_number();
	output_->on_connected();
}

void test_sync_server_client::disconnect() {
	LOG_INFO("Client disconnected");
	server_ = nullptr;
	output_->on_disconnected(std::nullopt);
}

// t: later on have events to emulate disconnected server
bool test_sync_server_client::handle_events() {
	assert(output_);
	bool ret = false;
	if(server_) {
		while(last_pushed_record_ < server_->sync.current_sequence_number()) {
			auto recs = server_->sync.get_records(last_pushed_record_+1, server_->sync.current_sequence_number());
			for(auto&& rec : recs) {
				output_->on_record_received(rec);
				ret = true;
			}
			last_pushed_record_ += recs.size();
		}
	}
	// take the events out in case handling an event adds another event
	std::deque<std::function<void()>> events;
	events.swap(events_);

	for(auto&& event : events) {
		event();
		ret = true;
	}
	return ret;
}

request_handle test_sync_server_client::fetch_sequence_number() {
	assert(output_ && server_);
	request_handle ret = ++req_handle;
	events_.push_back([=, this] {
		output_->on_sequence_number_response(ret, server_->sync.current_sequence_number());
	});
	return ret;
}

request_handle test_sync_server_client::fetch_records(sequence_number start, sequence_number end) {
	assert(output_ && server_);
	request_handle ret = ++req_handle;
	events_.push_back([=, this] {
			output_->on_record_response(ret, record_response{end, server_->sync.current_sequence_number(), server_->sync.get_records(start, end)});
	});
	return ret;
}

request_handle test_sync_server_client::fetch_data(sequence_number record) {
	assert(output_ && server_);
	request_handle ret = ++req_handle;
	events_.push_back([=, this] {
		//t: implement when data handling is done
		//virtual void on_data_response(request_handle, result<record_data_handle> const&) = 0;
	});
	return ret;
}

request_handle test_sync_server_client::commit_record(record_handle h) {
	assert(output_);
	request_handle ret = ++req_handle;
	if(server_) {
		events_.push_back([=, this, record = h->record()] {
				auto commit_result = server_->sync.commit_block(record);
				output_->on_commit_response(ret, commit_response{server_->sync.current_sequence_number(), commit_result});
		});
	}
	return ret;
}

sync::progress& test_sync_server_client::progress() const {
	return progress_;
}

record_storage& test_sync_server_client::records() const {
	return storage_;
}

test_sync_server_client_context::test_sync_server_client_context(int n, sync_mode mode, auth_mode amode)
: database{create_test_database("test_sync_server_client_" + std::to_string(n) + ".db")}
, engine_config{.mode=mode, .auth_mode=amode, .log_id=std::to_string(n)}
{
	// own public key needs to be in the public key access that is given to the sync engine
	pkeys.insert(user_key.public_key());
	pdata.set_my_private_key(user_key);
	io.set_output(engine);
}

test_sync_server::test_sync_server(chain_sync_config config)
: sync(database, config)
{
}

test_sync_context::test_sync_context(chain_sync_config config)
: mode(config.mode)
, amode(config.auth_mode)
, server(config)
{
}

void test_sync_context::add_client(bool connect, int num) {
	for(int i = 0; i != num; ++i) {
		clients.push_back(std::make_unique<test_sync_server_client_context>(clients.size()+1, mode));
		if(connect) {
			clients.back()->io.connect(server);
		}
	}
}

test_sync_server_client_context& test_sync_context::client(int num) {
	assert(num < clients.size());
	return *clients[num];
}

void test_sync_context::connect_client(int n) {
	client(n).io.connect(server);
}

void test_sync_context::disconnect_client(int n) {
	client(n).io.disconnect();
}

bool test_sync_context::handle_events() {
	LOG_INFO("handle_events start");
	bool ret = false;
	for(auto&& v : clients) {
		ret |= v->io.handle_events();
	}
	LOG_INFO("handle_events end");
	return ret;
}

void test_sync_context::create_initial_record() {
	if(!clients.empty()) {
		// set initial key, use hard coded one for testing
		encryption_key initial_key{sequence_number{1}, to_octet_vector("12345678901234567890123456789012")};
		users initial;

		bool first = true;
		for(auto&& c : clients) {
			if(first) {
				first = false;
				initial.add(util::user_access{c->user, util::access_type::user_management_access});
			} else {
				initial.add(util::user_access{c->user, util::access_type::data_write_access});
			}
			// insert the key for everyone
			c->enc_keys.insert(initial_key);
			// the first user does the initial change and so needs everyone's key
			clients.front()->pkeys.insert(c->user_key.public_key());
		}
		clients.front()->engine.sync_user_change(encrypt_last_key_for_users(initial, clients.front()->cc));
	}
}

bool test_sync_context::compare_record_storages(sequence_number required_seq) const {
	record_storage const& server_records = server.sync.records();
	sequence_number last_seq = server_records.last_block().sequence;
	bool ret = !required_seq.is_valid() || required_seq == last_seq;
	if(!ret) {
		LOG_WARN("Server doesn't have required sequence as last one: server({}) != {}", last_seq, required_seq);
	}
	for(int i = 0; ret && i != clients.size(); ++i) {
		record_storage const& client_records = clients[i]->io.records();
		if(last_seq != client_records.last_block().sequence) {
			ret = false;
			LOG_WARN("last sequence number mismatch: server({}) - client {}({})", last_seq, i, client_records.last_block().sequence);
		} else {
			for(sequence_number seq{1}; ret && seq != last_seq+1; ++seq) {
				ret = check_record_matches(seq, i, server_records.find(seq), client_records.find(seq));
			}
		}
	}
	return ret;
}

}
