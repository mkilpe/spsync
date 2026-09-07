#include "test_sync_server.hpp"
#include <spsync/client/record_util.hpp>
#include <spsync/core/user_merge.hpp>
#include <spsync/core/records/segment_record.hpp>
#include <spsync/engine/record_verifier.hpp>

#include <securepath/test_frame/test_utils.hpp>

#include <format>
#include <iostream>
#include <limits>
#include <string_view>

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
				output_->on_record_received(rec, {});
				ret = true;
			}
			last_pushed_record_ += recs.size();
		}
	}
	// take the events out in case handling an event adds another event
	std::deque<std::move_only_function<void()>> events;
	events.swap(events_);

	for(auto&& event : events) {
		event();
		ret = true;
	}
	return ret;
}

request_handle test_sync_server_client::fetch_sequence_number() {
	assert(output_);
	request_handle ret = ++req_handle;
	events_.push_back([=, this] {
		// the client may have disconnected (or hopped servers) before this ran
		if(server_) {
			output_->on_sequence_number_response(ret, sequence_info{server_->sync.current_sequence_number(), server_->id});
		}
	});
	return ret;
}

request_handle test_sync_server_client::fetch_records(sequence_number start, sequence_number end) {
	assert(output_);
	request_handle ret = ++req_handle;
	events_.push_back([=, this] {
			if(server_) {
				output_->on_record_response(ret, record_response{end, server_->sync.current_sequence_number(), server_->sync.get_records(start, end)});
			}
	});
	return ret;
}

request_handle test_sync_server_client::fetch_data(sequence_number record) {
	assert(output_);
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
				if(server_) {
					auto commit_result = server_->sync.commit_block(record);
					output_->on_commit_response(ret, commit_response{server_->sync.current_sequence_number(), commit_result});
				}
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

test_sync_server::test_sync_server(chain_sync_config config, std::string const& db_name)
: database(create_test_database(db_name))
, sync(database, config)
, id(securepath::test::random_octet_vector(32))
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
		clients.push_back(std::make_unique<test_sync_server_client_context>(clients.size()+1, mode, amode));
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
	bool ret = replicate_tick();
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

void test_sync_context::commit_storm(int records_per_client, bool special_mid_storm) {
	for(int i = 0; i != records_per_client; ++i) {
		if(special_mid_storm && i == records_per_client/2) {
			users delta{users_change_mode::delta};
			delta.add(util::user_access{clients.front()->user, util::access_type::user_management_access});
			clients.front()->engine.sync_user_change(encrypt_last_key_for_users(delta, clients.front()->cc));
		}
		for(auto&& c : clients) {
			c->engine.sync_object_change(util::create_object_id(), metadata{});
		}
	}
	while(handle_events()) {}
}

std::size_t test_sync_context::add_server(std::string const& db_name) {
	extra_servers.push_back(std::make_unique<test_sync_server>(
		chain_sync_config{mode, amode, db_name}, db_name));
	return extra_servers.size();
}

test_sync_server& test_sync_context::server_n(std::size_t n) {
	assert(n <= extra_servers.size());
	return n == 0 ? server : *extra_servers[n - 1];
}

test_sync_server const& test_sync_context::server_n(std::size_t n) const {
	assert(n <= extra_servers.size());
	return n == 0 ? server : *extra_servers[n - 1];
}

std::size_t test_sync_context::server_count() const {
	return extra_servers.size() + 1;
}

namespace {

std::string short_tag(octet_vector const& tag) {
	auto hex = to_hex(tag);
	return hex.substr(0, std::min<std::size_t>(8, hex.size()));
}

std::string_view type_name(record_type_tag type) {
	switch(type) {
	case user_change_record_tag: return "user change";
	case data_change_record_tag: return "data change";
	case segment_record_tag: return "segment";
	}
	return "unknown";
}

}

void test_sync_context::add_link(std::size_t a, std::size_t b, int delay) {
	links.push_back(replication_link{a, b, true, delay});
	if(trace_) {
		if(delay != 0) {
			std::cout << std::format("link   {} <-> {} created (delay {} ticks)\n", a, b, delay);
		} else {
			std::cout << std::format("link   {} <-> {} created\n", a, b);
		}
	}
}

void test_sync_context::set_link(std::size_t a, std::size_t b, bool up) {
	for(auto& l : links) {
		if((l.a == a && l.b == b) || (l.a == b && l.b == a)) {
			if(trace_ && l.up != up) {
				std::cout << std::format("link   {} <-> {} {}\n", a, b, up ? "up" : "DOWN  (partition)");
			}
			l.up = up;
		}
	}
}

void test_sync_context::connect_client_to(int n, std::size_t server_index) {
	client(n).io.connect(server_n(server_index));
}

/// move records one direction over a link; delivery goes through commit_foreign so
/// duplicates and op races dedup exactly like the real anti-entropy (plan 4.2/4.4)
bool test_sync_context::pump_link(replication_link& l, bool ab_direction) {
	auto const source = ab_direction ? l.a : l.b;
	auto const dest = ab_direction ? l.b : l.a;
	auto& from = server_n(source);
	auto& to = server_n(dest);
	auto& dir = ab_direction ? l.ab : l.ba;

	auto const head = from.sync.current_sequence_number();
	if(head < dir.scanned) {
		dir.scanned = sequence_number{};
	}
	sequence_number next{dir.scanned.value + 1};
	while(next.is_valid() && next <= head) {
		auto recs = from.sync.get_records(next, head);
		if(recs.empty()) {
			next = sequence_number{};
		} else {
			for(auto& rec : recs) {
				if(dir.seen.insert(rec.tag()).second) {
					dir.queue.push_back({l.delay, std::move(rec)});
				}
			}
			next = recs.back().sequence() + 1;
		}
	}
	dir.scanned = head;

	bool moved = false;
	for(auto& [countdown, rec] : dir.queue) {
		--countdown;
	}
	while(!dir.queue.empty() && dir.queue.front().first < 0) {
		auto const& rec = dir.queue.front().second;
		auto res = to.sync.commit_foreign(rec);
		if(res) {
			moved = true;
			// remember where the record came from for the narration
			replicated_from_[{dest, rec.tag()}] = source;
		}
		dir.queue.pop_front();
	}
	// records still aging in the queue keep the tick loop alive
	return moved || !dir.queue.empty();
}

bool test_sync_context::replicate_tick() {
	bool moved = false;
	for(auto& l : links) {
		if(l.up) {
			moved |= pump_link(l, true);
			moved |= pump_link(l, false);
		}
	}
	if(trace_) {
		trace_progress();
	}
	return moved;
}

/// narrate every record that landed since the last tick, per server
void test_sync_context::trace_progress() {
	for(std::size_t s = 0; s != server_count(); ++s) {
		auto const& records = server_n(s).sync.records();
		auto const head = server_n(s).sync.current_sequence_number();
		for(auto seq = traced_[s] + 1; seq <= head; ++seq) {
			auto h = records.find(seq);
			if(h) {
				auto from = replicated_from_.find({s, h->tag()});
				if(from != replicated_from_.end()) {
					std::cout << std::format("[server {}] replicate  #{:<3} {:<11}  tag {}  (from server {})\n",
						s, seq.value, type_name(h->type()), short_tag(h->tag()), from->second);
				} else {
					std::cout << std::format("[server {}] commit     #{:<3} {:<11}  tag {}\n",
						s, seq.value, type_name(h->type()), short_tag(h->tag()));
				}
			}
		}
		traced_[s] = head;
	}
}

namespace {

/// candidate-key decrypt of a user change (colliding key sequences try each key, D9)
std::optional<users> decrypt_user_change(chain_block const& block, user_change_record const& rec,
	encryption_key_storage const& keys) {
	std::optional<users> ret;
	for(auto const& key : keys.find_all(rec.encryption_key())) {
		if(!ret) {
			try {
				user_change_record_verifier ver(key, rec, block.auth());
				if(ver.is_authentic()) {
					ret = ver.data().access();
				}
			} catch(std::exception const&) {
			}
		}
	}
	return ret;
}

std::set<octet_vector> op_set(test_sync_server const& s) {
	std::set<octet_vector> ops;
	for(auto const& h : s.sync.records().find_range(sequence_number{1},
		sequence_number{std::numeric_limits<std::uint64_t>::max()})) {
		auto block = h->record();
		ops.insert(block.deserialise_record<octet_vector>([](auto const& rec) { return rec.op_id(); }));
	}
	return ops;
}

std::vector<util::user_access> derive_membership(test_sync_server const& s, encryption_key_storage const& keys) {
	std::vector<user_change_entry> entries;
	std::map<record_tag, record_tag> parent_special;
	for(auto const& h : s.sync.records().find_all_of_type(segment_record_tag)) {
		auto block = h->record();
		parent_special[block.tag()] = block.deserialise_to<segment_record>().last_seen_special_tag();
	}
	for(auto const& h : s.sync.records().find_all_of_type(user_change_record_tag)) {
		auto block = h->record();
		auto rec = block.deserialise_to<user_change_record>();
		parent_special[block.tag()] = rec.last_seen_special_tag();
		if(auto us = decrypt_user_change(block, rec, keys)) {
			entries.push_back(user_change_entry{std::move(*us), block.tag(), rec.last_seen_special_tag()});
		}
	}
	return merge_user_changes(entries, parent_special);
}

/// the decrypted data change contents: (object id, decrypted header) occurrences
std::multiset<std::pair<octet_vector, octet_vector>> message_set(test_sync_server const& s,
	encryption_key_storage const& keys) {
	std::multiset<std::pair<octet_vector, octet_vector>> ret;
	for(auto const& h : s.sync.records().find_all_of_type(data_change_record_tag)) {
		auto block = h->record();
		auto rec = block.deserialise_to<data_change_record>();
		for(auto const& key : keys.find_all(rec.encryption_key())) {
			try {
				data_change_record_verifier ver(key, rec, block.auth());
				if(ver.is_authentic()) {
					for(auto const& change : ver.headers()) {
						ret.insert({change.data.id.value(), serialisation::asn_der_serialise(change.header)});
					}
					break;
				}
			} catch(std::exception const&) {
			}
		}
	}
	return ret;
}

}

void test_sync_context::print_summary() const {
	assert(!clients.empty());
	auto const& keys = clients.front()->enc_keys;

	std::cout << "\n=== final situation ===\n";
	for(std::size_t s = 0; s != server_count(); ++s) {
		auto const& srv = server_n(s);
		auto const members = derive_membership(srv, keys);
		std::string member_list;
		for(auto const& m : members) {
			member_list += (member_list.empty() ? "" : ", ") + short_tag(m.user.public_key_id().data());
		}
		std::cout << std::format("server {}: {} records, {} ops, {} messages, members: [{}]\n",
			s, srv.sync.current_sequence_number().value, op_set(srv).size(),
			message_set(srv, keys).size(), member_list);

		// the local apply order: replicas may observe the same changes differently (D4)
		std::string line = "  order:";
		int on_line = 0;
		for(auto const& h : srv.sync.records().find_range(sequence_number{1},
			sequence_number{std::numeric_limits<std::uint64_t>::max()})) {
			if(on_line == 8) {
				std::cout << line << "\n";
				line = "        ";
				on_line = 0;
			}
			line += std::format(" {}({:.1})", short_tag(h->tag()), type_name(h->type()));
			++on_line;
		}
		std::cout << line << "\n";
	}
	// what each client sees: its own storage synced from the server it is attached to
	for(std::size_t c = 0; c != clients.size(); ++c) {
		auto const& io = clients[c]->io;
		auto const& records = io.records();

		std::string on = "disconnected";
		std::vector<octet_vector> server_order;
		if(io.connected_server()) {
			for(std::size_t s = 0; s != server_count(); ++s) {
				if(&server_n(s) == io.connected_server()) {
					on = std::format("on server {}", s);
					for(auto const& h : server_n(s).sync.records().find_range(sequence_number{1},
						sequence_number{std::numeric_limits<std::uint64_t>::max()})) {
						server_order.push_back(h->tag());
					}
				}
			}
		}

		std::vector<octet_vector> order;
		std::string line = "  order:";
		int on_line = 0;
		for(auto const& h : records.find_range(sequence_number{1},
			sequence_number{std::numeric_limits<std::uint64_t>::max()})) {
			order.push_back(h->tag());
			if(on_line == 8) {
				line += "\n        ";
				on_line = 0;
			}
			line += std::format(" {}({:.1})", short_tag(h->tag()), type_name(h->type()));
			++on_line;
		}

		std::size_t pending = 0;
		for(auto h = records.find_first_pending_commit(); h; h = records.find_next_pending_commit(h)) {
			++pending;
		}

		std::cout << std::format("client {} ({}): {} records, {} pending\n",
			c, on, order.size(), pending);
		if(io.connected_server() && order == server_order) {
			std::cout << "  order: same as its server\n";
		} else {
			std::cout << line << "\n";
		}
	}
	std::cout << std::format("converged: {}\n\n", servers_converged() ? "YES" : "NO");
}

bool test_sync_context::servers_converged() const {
	assert(!clients.empty());
	auto const& keys = clients.front()->enc_keys;

	auto const ops = op_set(server_n(0));
	auto const members = derive_membership(server_n(0), keys);
	auto const messages = message_set(server_n(0), keys);

	bool ret = true;
	for(std::size_t i = 1; i < server_count(); ++i) {
		if(op_set(server_n(i)) != ops) {
			LOG_WARN("op id sets differ [server 0 vs {}]", i);
			ret = false;
		} else if(derive_membership(server_n(i), keys) != members) {
			LOG_WARN("derived memberships differ [server 0 vs {}]", i);
			ret = false;
		} else if(message_set(server_n(i), keys) != messages) {
			LOG_WARN("decrypted message sets differ [server 0 vs {}]", i);
			ret = false;
		}
	}
	return ret;
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
