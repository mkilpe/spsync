#include <spsync/test/engine_context.hpp>

#include <spsync/core/data/source_record_data.hpp>
#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>
#include <spsync/core/records/user_change_record.hpp>

#include <spsync/protocol/error.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <atomic>
#include <fstream>
#include <mutex>

namespace securepath::sync::util {
namespace {

using namespace std::chrono_literals;

struct data_observer : sync::engine_output {
	using engine_output::engine_output;
	~data_observer() { stop_handler(); }

	void on_data_state_changed(data_id id, record_data_state state) override {
		std::unique_lock lock{mutex};
		states.emplace_back(std::move(id), state);
		++state_changes;
	}

	void on_data_transfer_failed(data_id id, error) override {
		std::unique_lock lock{mutex};
		failed.push_back(std::move(id));
		++failures;
	}

	std::atomic<int> state_changes{0};
	std::atomic<int> failures{0};
	std::mutex mutex;
	std::vector<std::pair<data_id, record_data_state>> states;
	std::vector<data_id> failed;
};

/// a context with the initial record committed
struct data_context : test::engine_context {
	data_context() {
		add_default_commit_response();
		create_initial_record();
		io.process_events();
		engine.set_output(&observer);
	}

	~data_context() {
		engine.set_output(nullptr);
	}

	/// the data id the record's first change names
	data_id data_of(record_handle const& h) const {
		auto const rec = h->record().deserialise_to<data_change_record>();
		return rec.begin()->data.data.value().manifest_digest;
	}

	data_observer observer{single_thread_event_loop};
};

/// a member that joins somebody else's chain: the group key, no records of its own
struct reader_context : test::engine_context {
	reader_context() {
		enc_keys.insert(encryption_key{sequence_number{1}, to_octet_vector("12345678901234567890123456789012")});
		engine.set_output(&observer);
	}

	~reader_context() {
		engine.set_output(nullptr);
	}

	data_observer observer{single_thread_event_loop};
};

octet_vector read_all(record_data& data) {
	octet_vector ret(data.size());
	ret.resize(data.read(0, ret.data(), ret.size()));
	return ret;
}

}

// RD7: the source is streamed into the store, the record commits without waiting for
// the upload, the upload is asked for once the record exists on the server
TEST_CASE("engine data change commits then uploads", "[unit]") {
	data_context context;
	// the default chunk size is 1 MiB: three chunks
	auto const content = securepath::test::random_octet_vector(2 * 1024 * 1024 + 500000);

	auto h = context.engine.sync_object_change(create_object_id(), metadata{}, std::make_shared<memory_record_data>(content));
	REQUIRE(h);
	CHECK(h->state() == record_state::pending_commit);

	// the record names the data, the data is held and waits for its upload
	auto const id = context.data_of(h);
	auto const row = context.data_store.find(id);
	REQUIRE(row);
	CHECK(row->state == record_data_state::upload_pending);
	CHECK(row->have.size() == 3);
	CHECK(row->have.complete());
	CHECK(context.storage.data_reference_count(row->local_id) == 1);

	// nothing is uploaded for a record the server does not have
	CHECK(context.io.upload_requests().empty());

	context.add_default_commit_response();
	CHECK(context.io.process_event());
	CHECK(h->state() == record_state::in_sync);
	CHECK(context.io.upload_requests() == std::vector<data_id>{id});
	CHECK(context.data_store.find(id)->state == record_data_state::upload_pending);

	// readable all along
	auto data = context.engine.object_data(h);
	REQUIRE(data);
	CHECK(data->state() == record_data_state::upload_pending);
	CHECK(data->size() == content.size());
	CHECK(read_all(*data) == content);
	CHECK(!context.engine.object_data(h, 1));
	CHECK(!context.engine.object_data(context.storage.find_root()));

	context.io.add_upload_data_response([](data_id const&) { return std::nullopt; });
	CHECK(context.io.process_event());
	CHECK(data->state() == record_data_state::in_sync);
	WAIT_CHECK(context.observer.state_changes == 1, 2s);
	REQUIRE(context.observer.states.size() == 1);
	CHECK(context.observer.states[0] == std::pair{id, record_data_state::in_sync});

	// nothing more is owed
	context.add_default_commit_response();
	context.engine.sync_object_change(create_object_id(), metadata{});
	context.io.process_events();
	CHECK(context.io.upload_requests().size() == 1);
}

TEST_CASE("engine data change without data keeps no data", "[unit]") {
	data_context context;
	context.add_default_commit_response();
	auto h = context.engine.sync_object_change(create_object_id(), metadata{});
	context.io.process_events();
	CHECK(h->state() == record_state::in_sync);
	CHECK(!context.engine.object_data(h));
	CHECK(context.io.upload_requests().empty());
}

// RD4: uploads are asked for in the commit order of their records
TEST_CASE("engine uploads in commit order", "[unit]") {
	data_context context;
	auto first = context.engine.sync_object_change(create_object_id(), metadata{}
		, std::make_shared<memory_record_data>(securepath::test::random_octet_vector(3000)));
	auto second = context.engine.sync_object_change(create_object_id(), metadata{}
		, std::make_shared<memory_record_data>(securepath::test::random_octet_vector(100)));
	CHECK(context.io.upload_requests().empty());

	context.add_default_commit_response();
	context.add_default_commit_response();
	context.io.process_events();
	REQUIRE(first->state() == record_state::in_sync);
	REQUIRE(second->state() == record_state::in_sync);
	CHECK(context.io.upload_requests() == std::vector<data_id>{context.data_of(first), context.data_of(second)});
}

// the connection goes while the data is on its way: asked again after the reconnect
TEST_CASE("engine resumes an interrupted upload", "[unit]") {
	data_context context;
	context.add_default_commit_response();
	auto h = context.engine.sync_object_change(create_object_id(), metadata{}
		, std::make_shared<memory_record_data>(securepath::test::random_octet_vector(5000)));
	auto const id = context.data_of(h);
	context.io.process_events();
	REQUIRE(context.io.upload_requests().size() == 1);

	// no answer: the upload is on its way; more events do not ask twice
	context.add_default_commit_response();
	context.engine.sync_object_change(create_object_id(), metadata{});
	context.io.process_events();
	CHECK(context.io.upload_requests().size() == 1);

	context.engine.on_disconnected({});
	context.engine.on_connected();
	context.io.process_events();
	CHECK(context.io.upload_requests() == std::vector<data_id>{id, id});
	CHECK(context.data_store.find(id)->state == record_data_state::upload_pending);

	// the answer of the first try is of a connection that is gone
	context.engine.on_data_uploaded(1000, std::nullopt);
	CHECK(context.data_store.find(id)->state == record_data_state::upload_pending);

	context.io.add_upload_data_response([](data_id const&) { return std::nullopt; });
	context.engine.on_disconnected({});
	context.engine.on_connected();
	context.io.process_events();
	CHECK(context.io.upload_requests().size() == 3);
	CHECK(context.data_store.find(id)->state == record_data_state::in_sync);

	// uploaded: a reconnect owes nothing
	context.engine.on_disconnected({});
	context.engine.on_connected();
	context.io.process_events();
	CHECK(context.io.upload_requests().size() == 3);
}

// a refused upload is reported and left alone until the next connect
TEST_CASE("engine upload failure", "[unit]") {
	data_context context;
	context.add_default_commit_response();
	context.io.add_upload_data_response([](data_id const&) {
		return make_error(securepath::errc::constraint_violation, "quota exceeded"); });
	auto h = context.engine.sync_object_change(create_object_id(), metadata{}
		, std::make_shared<memory_record_data>(securepath::test::random_octet_vector(5000)));
	auto const id = context.data_of(h);
	context.io.process_events();

	WAIT_CHECK(context.observer.failures == 1, 2s);
	REQUIRE(context.observer.failed.size() == 1);
	CHECK(context.observer.failed[0] == id);
	CHECK(context.data_store.find(id)->state == record_data_state::upload_pending);
	CHECK(context.observer.state_changes == 0);

	// not asked again while connected...
	context.add_default_commit_response();
	context.engine.sync_object_change(create_object_id(), metadata{});
	context.io.process_events();
	CHECK(context.io.upload_requests().size() == 1);

	// ...but after the next connect
	context.io.add_upload_data_response([](data_id const&) { return std::nullopt; });
	context.engine.on_disconnected({});
	context.engine.on_connected();
	context.io.process_events();
	CHECK(context.io.upload_requests().size() == 2);
	CHECK(context.data_store.find(id)->state == record_data_state::in_sync);
}

// a change that cannot become a record leaves no data behind
TEST_CASE("engine refused data change leaves no data", "[unit]") {
	data_context context;
	// the storage's limits as the server reports them on attach
	context.engine.on_sequence_number_response(100, sequence_info{sequence_number{1}, {}, storage_limits{4096, 256 * 1024}});

	metadata big{{"text", securepath::test::random_octet_vector(8000)}};
	CHECK_THROWS(context.engine.sync_object_change(create_object_id(), big
		, std::make_shared<memory_record_data>(securepath::test::random_octet_vector(600000))));
	data_state_table table{context.database};
	CHECK(table.all_ids().empty());
	CHECK(std::filesystem::is_empty(context.data_root / ".staging"));
	std::size_t entries = 0;
	for(auto const& e : std::filesystem::directory_iterator{context.data_root}) {
		entries += e.path().filename() == ".staging" ? 0 : 1;
	}
	CHECK(entries == 0);

	// the learned chunk size cuts the next data: 600000 octets pad to three 256 KiB chunks
	context.add_default_commit_response();
	auto h = context.engine.sync_object_change(create_object_id(), metadata{}
		, std::make_shared<memory_record_data>(securepath::test::random_octet_vector(600000)));
	auto const row = context.data_store.find(context.data_of(h));
	REQUIRE(row);
	CHECK(row->descriptor.chunk_size == 256 * 1024);
	CHECK(row->have.size() == 3);

	// a source that ends short is refused before anything is created
	struct short_source : memory_record_data {
		using memory_record_data::memory_record_data;
		std::uint64_t size() const override { return memory_record_data::size() + 10; }
	};
	CHECK_THROWS(context.engine.sync_object_change(create_object_id(), metadata{}
		, std::make_shared<short_source>(securepath::test::random_octet_vector(100))));
	CHECK(table.all_ids().size() == 1);
	CHECK(std::filesystem::is_empty(context.data_root / ".staging"));
}

TEST_CASE("engine data change from a file", "[unit]") {
	data_context context;
	std::filesystem::path const path = "engine_test_source.bin";
	auto const content = securepath::test::random_octet_vector(70000);
	{
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		out.write(reinterpret_cast<char const*>(content.data()), static_cast<std::streamsize>(content.size()));
	}

	context.add_default_commit_response();
	auto h = context.engine.sync_object_change(create_object_id(), metadata{}, std::make_shared<file_record_data>(path));
	context.io.process_events();
	auto data = context.engine.object_data(h);
	REQUIRE(data);
	CHECK(read_all(*data) == content);
	std::filesystem::remove(path);

	CHECK_THROWS(file_record_data{"engine_test_no_such_file.bin"});
}

// the engine of a storage without a data store refuses data
TEST_CASE("engine without a data store", "[unit]") {
	test::engine_context base;
	test::comm_test_interface io{base.progress, base.storage};
	test::test_sync_engine engine{base.single_thread_event_loop, io, base.cc, {}};
	io.set_output(engine);
	CHECK_THROWS(engine.sync_object_change(create_object_id(), metadata{}
		, std::make_shared<memory_record_data>(securepath::test::random_octet_vector(100))));
}

// RDS 6: data of others is deferred until asked for (lazy, RD6); asking fetches it and
// the state tells how it went
TEST_CASE("engine fetches record data", "[unit]") {
	auto const content = securepath::test::random_octet_vector(300000);

	// the author's side first: the test contexts share a database file name, so the
	// reader is made when the author is done, from what the author left in memory
	std::deque<chain_block> blocks;
	data_manifest manifest;
	std::vector<octet_vector> chunks;
	data_id id;
	record_tag sent_tag;
	record_tag again_tag;
	{
		data_context author;
		author.add_default_commit_response();
		auto sent = author.engine.sync_object_change(create_object_id(), metadata{}, std::make_shared<memory_record_data>(content));
		author.io.process_events();
		REQUIRE(sent->state() == record_state::in_sync);
		id = author.data_of(sent);
		sent_tag = sent->tag();
		manifest = author.data_store.manifest(id).value();
		for(std::uint64_t no = 0; no != manifest.chunk_digests.size(); ++no) {
			chunks.push_back(author.data_store.read_chunk(id, no).value());
		}
		// the same content once more, as another object
		author.add_default_commit_response();
		auto again = author.engine.sync_object_change(create_object_id(), metadata{}, std::make_shared<memory_record_data>(content));
		author.io.process_events();
		REQUIRE(again->state() == record_state::in_sync);
		REQUIRE(author.data_of(again) != id);
		again_tag = again->tag();
		for(sequence_number seq{1}; seq <= author.storage.last_block().sequence; ++seq) {
			auto const h = author.storage.find(seq);
			auto block = h->record();
			block.set_sequence_and_parent_hash(h->block_id().sequence, h->parent_block_hash());
			blocks.push_back(block);
		}
	}

	reader_context reader;
	for(auto const& block : blocks) {
		reader.engine.on_record_received(block);
	}
	auto received = reader.storage.find_tag(sent_tag);
	REQUIRE(received);
	REQUIRE(received->state() == record_state::in_sync);

	// lazy: known, not asked for
	auto data = reader.engine.object_data(received);
	REQUIRE(data);
	CHECK(data->state() == record_data_state::deferred);
	CHECK(data->size() == content.size());
	CHECK(reader.io.fetch_requests().empty());

	/// what comm does for a fetch: the first n chunks of the ciphertext into the reader's store
	auto const copy_chunks = [&](std::uint64_t n) {
		return [&, n](data_id const& wanted) -> std::optional<error> {
			bool ok = reader.data_store.set_manifest(wanted, manifest);
			for(std::uint64_t no = 0; ok && no != n; ++no) {
				ok = reader.data_store.store_chunk(wanted, no, chunks[no]);
			}
			auto const complete = reader.data_store.find(wanted)->state == record_data_state::in_sync;
			return complete ? std::nullopt : std::optional<error>{make_error(protocol::errc::data_not_held)};
		};
	};
	auto const chunk_count = chunks.size();

	SECTION("fetched") {
		reader.io.add_fetch_data_response(copy_chunks(chunk_count));
		auto fetched = reader.engine.fetch_object_data(received);
		REQUIRE(fetched);
		CHECK(fetched->state() == record_data_state::download_pending);
		CHECK(reader.io.fetch_requests() == std::vector<data_id>{id});
		// asking again while it is on its way asks nothing new
		reader.engine.fetch_object_data(received);
		CHECK(reader.io.fetch_requests().size() == 1);

		reader.io.process_events();
		CHECK(fetched->state() == record_data_state::in_sync);
		octet_vector read_back(content.size());
		CHECK(fetched->read(0, read_back.data(), read_back.size()) == content.size());
		CHECK(read_back == content);
		WAIT_CHECK(reader.observer.state_changes == 2, 2s);
		REQUIRE(reader.observer.states.size() == 2);
		CHECK(reader.observer.states[0] == std::pair{id, record_data_state::download_pending});
		CHECK(reader.observer.states[1] == std::pair{id, record_data_state::in_sync});

		// held: nothing to fetch
		reader.engine.fetch_object_data(received);
		CHECK(reader.io.fetch_requests().size() == 1);
	}

	SECTION("remote not complete, then notified") {
		// the author's upload is still in progress: the holders have nothing of it yet
		reader.io.add_fetch_data_response(copy_chunks(0));
		auto fetched = reader.engine.fetch_object_data(received);
		reader.io.process_events();
		CHECK(fetched->state() == record_data_state::remote_not_complete);
		CHECK(reader.io.fetch_requests().size() == 1);

		// a notification for some other data changes nothing
		reader.engine.on_data_available(securepath::test::random_octet_vector(64), true);
		CHECK(reader.io.fetch_requests().size() == 1);

		// notify_data: the data is there now
		reader.io.add_fetch_data_response(copy_chunks(chunk_count));
		reader.engine.on_data_available(id, true);
		CHECK(fetched->state() == record_data_state::download_pending);
		CHECK(reader.io.fetch_requests() == std::vector<data_id>{id, id});
		reader.io.process_events();
		CHECK(fetched->state() == record_data_state::in_sync);
	}

	SECTION("failed, asked again") {
		reader.io.add_fetch_data_response([](data_id const&) {
			return make_error(protocol::errc::data_transfer_quota_exceeded); });
		auto fetched = reader.engine.fetch_object_data(received);
		reader.io.process_events();
		CHECK(fetched->state() == record_data_state::download_pending);
		WAIT_CHECK(reader.observer.failures == 1, 2s);

		// left alone while connected...
		reader.add_default_commit_response();
		reader.engine.sync_object_change(create_object_id(), metadata{});
		reader.io.process_events();
		CHECK(reader.io.fetch_requests().size() == 1);

		// ...until it is asked for again
		reader.io.add_fetch_data_response(copy_chunks(chunk_count));
		reader.engine.fetch_object_data(received);
		CHECK(reader.io.fetch_requests().size() == 2);
		reader.io.process_events();
		CHECK(fetched->state() == record_data_state::in_sync);
	}

	SECTION("a lost connection resumes the download") {
		auto fetched = reader.engine.fetch_object_data(received);
		reader.io.process_events();
		CHECK(reader.io.fetch_requests().size() == 1);

		reader.io.add_fetch_data_response(copy_chunks(chunk_count));
		reader.engine.on_disconnected({});
		reader.engine.on_connected();
		reader.io.process_events();
		CHECK(reader.io.fetch_requests().size() == 2);
		CHECK(fetched->state() == record_data_state::in_sync);
	}

	SECTION("the same content under another data id is not downloaded") {
		// the first copy comes down the usual way
		reader.io.add_fetch_data_response(copy_chunks(chunk_count));
		auto first = reader.engine.fetch_object_data(received);
		reader.io.process_events();
		REQUIRE(first->state() == record_data_state::in_sync);
		// download_pending and in_sync of the first one, delivered on the loop thread
		WAIT_REQUIRE(reader.observer.state_changes == 2, 2s);

		// the author sends the same file again: another nonce, another data id
		auto const again_received = reader.storage.find_tag(again_tag);
		REQUIRE(again_received);
		auto known = reader.engine.object_data(again_received);
		REQUIRE(known);
		CHECK(known->state() == record_data_state::deferred);

		auto fetched = reader.engine.fetch_object_data(again_received);
		REQUIRE(fetched);
		// made from what is held: nothing was asked from anybody
		CHECK(fetched->state() == record_data_state::in_sync);
		CHECK(reader.io.fetch_requests().size() == 1);
		octet_vector read_back(content.size());
		CHECK(fetched->read(0, read_back.data(), read_back.size()) == content.size());
		CHECK(read_back == content);
		WAIT_CHECK(reader.observer.state_changes == 3, 2s);
		REQUIRE(reader.observer.states.size() == 3);
		CHECK(reader.observer.states[2].second == record_data_state::in_sync);
		CHECK(reader.observer.states[2].first != id);
	}

	SECTION("evicted data is fetched again") {
		reader.io.add_fetch_data_response(copy_chunks(chunk_count));
		auto fetched = reader.engine.fetch_object_data(received);
		reader.io.process_events();
		REQUIRE(fetched->state() == record_data_state::in_sync);

		fetched->remove_data();
		CHECK(fetched->state() == record_data_state::removed);
		reader.io.add_fetch_data_response(copy_chunks(chunk_count));
		reader.engine.fetch_object_data(received);
		CHECK(reader.io.fetch_requests().size() == 2);
		reader.io.process_events();
		CHECK(fetched->state() == record_data_state::in_sync);
	}
}

}
