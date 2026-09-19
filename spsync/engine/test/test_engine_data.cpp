#include <spsync/test/engine_context.hpp>

#include <spsync/core/data/source_record_data.hpp>
#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>
#include <spsync/core/records/user_change_record.hpp>

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

}
