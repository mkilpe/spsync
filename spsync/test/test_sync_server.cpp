#include "test_sync_server.hpp"

namespace securepath::sync::test {

test_sync_server_client::test_sync_server_client(database::connection_ptr db)
: storage_(db)
{
}

void test_sync_server_client::set_output(comm_output& out) {
	output_ = &out;
}

void test_sync_server_client::connect(test_sync_server& server) {
	server_ = &server;
	last_pushed_record_ = server_->sync.current_sequence_number();
}

void test_sync_server_client::disconnect() {
	server_ = nullptr;
}

void test_sync_server_client::handle_events() {
	assert(output_);
	for(auto&& event : events_) {
		event();
	}
	if(server_) {
		if(last_pushed_record_ < server_->sync.current_sequence_number()) {
			for(auto&& rec : server_->sync.get_records(last_pushed_record_+1, server_->sync.current_sequence_number()+1)) {
				output_->on_record_received(rec);
			}
			last_pushed_record_ = server_->sync.current_sequence_number();
		}
	}
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
			output_->on_record_response(ret, server_->sync.get_records(start, end));
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
	assert(output_ && server_);
	request_handle ret = ++req_handle;
	events_.push_back([=, this] {
			output_->on_commit_response(ret, server_->sync.commit_block(h->record()));
	});
	return ret;
}

sync::progress& test_sync_server_client::progress() {
	return progress_;
}

record_storage& test_sync_server_client::records() {
	return storage_;
}

test_sync_server_client_context::test_sync_server_client_context() {
	io.set_output(engine);
}

test_sync_server::test_sync_server(chain_sync_config config)
: sync(database, config)
{
}

void test_sync_context::add_client(bool connect) {
	clients.push_back(std::make_unique<test_sync_server_client_context>());
	if(connect) {
		clients.back()->io.connect(server);
	}
}

void test_sync_context::handle_events() {
	for(auto&& v : clients) {
		v->io.handle_events();
	}
}

}
