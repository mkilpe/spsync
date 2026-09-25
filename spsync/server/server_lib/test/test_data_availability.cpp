// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/server/server_lib/data_availability.hpp>
#include <spsync/server/server_lib/data_release.hpp>
#include <spsync/server/server_lib/data_replication_plan.hpp>
#include <spsync/server/server_lib/peer_config.hpp>
#include <spsync/server/server_lib/ticket_issuer.hpp>
#include <spsync/protocol/error.hpp>
#include <spsync/test/test_record_data.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>

#include <algorithm>
#include <map>
#include <set>
#include <sstream>

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

std::vector<data_endpoint> make_endpoints(std::size_t n) {
	std::vector<data_endpoint> ret;
	for(std::size_t i = 0; i != n; ++i) {
		ret.push_back(data_endpoint{"10.0.0." + std::to_string(i + 1), static_cast<std::uint16_t>(18203 + i)
			, crypto::public_key_id{securepath::test::random_octet_vector(32)}, {}, {}});
	}
	return ret;
}

std::vector<crypto::public_key_id> keys_of(std::vector<data_endpoint> const& endpoints) {
	std::vector<crypto::public_key_id> ret;
	for(auto const& e : endpoints) {
		ret.push_back(e.key);
	}
	return ret;
}

/// what a chain accepts: three chunks of the default size
data_descriptor test_descriptor() {
	return test::test_descriptor(3 * 1024 * 1024, 1024 * 1024);
}

using test::is_error;

}

TEST_CASE("data availability table", "[unit]") {
	data_availability table;
	auto const sid = securepath::test::random_octet_vector(16);
	auto const id = securepath::test::random_octet_vector(64);
	auto const holder_a = crypto::public_key_id{securepath::test::random_octet_vector(32)};
	auto const holder_b = crypto::public_key_id{securepath::test::random_octet_vector(32)};

	CHECK(table.holdings(sid, id).empty());
	CHECK(table.load(holder_a) == holder_load{});

	table.announce(sid, id, data_holding{holder_a, 2, 5, false});
	table.announce(sid, id, data_holding{holder_b, 5, 5, true});
	CHECK(table.holdings(sid, id).size() == 2);

	// a later announcement of a holder replaces its earlier one
	table.announce(sid, id, data_holding{holder_a, 5, 5, true});
	auto const holdings = table.holdings(sid, id);
	REQUIRE(holdings.size() == 2);
	CHECK(std::ranges::all_of(holdings, [](data_holding const& h) { return h.complete; }));

	// per storage and per data
	CHECK(table.holdings(securepath::test::random_octet_vector(16), id).empty());
	CHECK(table.holdings(sid, securepath::test::random_octet_vector(64)).empty());

	table.set_load(holder_a, holder_load{1000, 3});
	CHECK(table.load(holder_a) == holder_load{1000, 3});
	CHECK(table.load(holder_b) == holder_load{});
}

// RD13: placement - the same everywhere, even, and stable when the set changes
TEST_CASE("data upload placement order", "[unit]") {
	auto const endpoints = make_endpoints(5);
	auto const id = securepath::test::random_octet_vector(64);

	auto const order = upload_order(endpoints, id);
	REQUIRE(order.size() == 5);
	CHECK(std::ranges::is_permutation(keys_of(order), keys_of(endpoints)));

	// every record server names the same order whatever order its configuration lists them in
	auto shuffled = endpoints;
	std::ranges::reverse(shuffled);
	CHECK(upload_order(shuffled, id) == order);
	CHECK(upload_order({}, id).empty());

	// the first place spreads over the set
	std::map<crypto::public_key_id, int> first;
	int const datas = 2000;
	for(int i = 0; i != datas; ++i) {
		++first[upload_order(endpoints, securepath::test::random_octet_vector(64)).front().key];
	}
	CHECK(first.size() == 5);
	for(auto const& [key, n] : first) {
		CHECK(n > datas / 5 / 2);
		CHECK(n < datas / 5 * 2);
	}

	// a server leaving moves only the data that was placed on it
	auto without_last = endpoints;
	without_last.pop_back();
	int moved = 0;
	int kept = 0;
	for(int i = 0; i != 500; ++i) {
		auto const d = securepath::test::random_octet_vector(64);
		auto const before = upload_order(endpoints, d).front().key;
		auto const after = upload_order(without_last, d).front().key;
		if(before == endpoints.back().key) {
			++moved;
		} else {
			kept += before == after ? 1 : 0;
		}
	}
	CHECK(moved + kept == 500);
}

// RDS 5: holder order by completeness and load
TEST_CASE("data download holder order", "[unit]") {
	auto const endpoints = make_endpoints(5);
	auto const id = securepath::test::random_octet_vector(64);
	auto const placement = upload_order(endpoints, id);
	data_availability table;

	// nothing known: where an upload would have gone
	CHECK(download_order(endpoints, id, {}, table) == placement);

	auto const& busy = placement[4];
	auto const& idle = placement[3];
	auto const& half = placement[2];
	auto const& little = placement[1];
	auto const& unknown = placement[0];
	std::vector<data_holding> const holdings{
		{little.key, 1, 10, false},
		{half.key, 5, 10, false},
		{busy.key, 10, 10, true},
		{idle.key, 10, 10, true},
		// a holder that is no data server of the storage (any more)
		{crypto::public_key_id{securepath::test::random_octet_vector(32)}, 10, 10, true}};
	table.set_load(busy.key, holder_load{5000, 4});
	table.set_load(idle.key, holder_load{9000, 0});

	auto const order = download_order(endpoints, id, holdings, table);
	REQUIRE(order.size() == 5);
	// complete and idle, complete and busy, the bigger part, the smaller part, nothing known
	CHECK(order[0] == idle);
	CHECK(order[1] == busy);
	CHECK(order[2] == half);
	CHECK(order[3] == little);
	CHECK(order[4] == unknown);

	// equal uploads in progress: the one storing less
	table.set_load(idle.key, holder_load{9000, 4});
	CHECK(download_order(endpoints, id, holdings, table)[0] == busy);

	// a holder announced with nothing held is as good as unknown
	std::vector<data_holding> const empty_holding{{placement[3].key, 0, 10, false}};
	CHECK(download_order(endpoints, id, empty_holding, table) == placement);
}

// RD12: what the record server states and to whom; RDS 5: a ticket for an unknown data is refused
TEST_CASE("data ticket issuer", "[unit]") {
	auto const server_key = crypto::generate_private_key();
	crypto::public_key_cache keys;
	keys.insert(server_key.public_key());
	auto const member = crypto::public_key_id{securepath::test::random_octet_vector(32)};
	auto const sid = securepath::test::random_octet_vector(16);
	auto const descriptor = test_descriptor();
	auto const& id = descriptor.manifest_digest;
	auto const now = clock_type::now();
	auto const upload = static_cast<std::uint32_t>(data_right::upload);
	auto const download = static_cast<std::uint32_t>(data_right::download);

	auto const endpoints = make_endpoints(4);
	data_availability table;
	ticket_issuer issuer{endpoints, table, 600s};
	CHECK(issuer.data_servers() == endpoints);

	// no ticket for a data the storage does not vouch for: its reason comes back
	CHECK(is_error(issuer.issue(sid, make_error(protocol::errc::unknown_data), member, upload, server_key, now), protocol::errc::unknown_data));
	CHECK(is_error(issuer.issue(sid, make_error(protocol::errc::data_pruned), member, upload, server_key, now), protocol::errc::data_pruned));
	CHECK(is_error(issuer.issue(sid, descriptor, member, 0, server_key, now), protocol::errc::invalid_state));
	CHECK(is_error(issuer.issue(sid, descriptor, member, 7, server_key, now), protocol::errc::invalid_state));
	CHECK(is_error(issuer.issue(sid, descriptor, member, upload, std::nullopt, now), protocol::errc::invalid_state));
	CHECK(is_error(ticket_issuer{{}, table, 600s}.issue(sid, descriptor, member, upload, server_key, now), protocol::errc::no_data_servers));

	auto const up = issuer.issue(sid, descriptor, member, upload, server_key, now);
	REQUIRE(up);
	CHECK(up->ticket.storage_id() == sid);
	CHECK(up->ticket.descriptor() == descriptor);
	CHECK(up->ticket.member() == member);
	CHECK(up->ticket.right() == data_right::upload);
	CHECK(up->ticket.issuer() == server_key.id());
	CHECK(!up->ticket.verify(keys, now));
	CHECK(!up->ticket.verify(keys, now + 599s));
	CHECK(up->ticket.verify(keys, now + 600s));
	CHECK(up->holders == upload_order(endpoints, id));

	// a download is sent to who has it
	auto const placement = upload_order(endpoints, id);
	table.announce(sid, id, data_holding{placement[3].key, 3, 3, true});
	auto const down = issuer.issue(sid, descriptor, member, download, server_key, now);
	REQUIRE(down);
	CHECK(down->ticket.right() == data_right::download);
	CHECK(!down->ticket.verify(keys, now));
	REQUIRE(down->holders.size() == 4);
	CHECK(down->holders[0] == placement[3]);
	CHECK(down->holders[1] == placement[0]);
	// the upload order is not moved by who holds what
	CHECK(issuer.issue(sid, descriptor, member, upload, server_key, now)->holders == placement);
}

// the cluster configuration form of a data server
TEST_CASE("data endpoint configuration", "[unit]") {
	auto const key = crypto::public_key_id{securepath::test::random_octet_vector(32)};

	data_endpoint plain;
	std::istringstream in{"data1.example.org:18203/" + key.in_hex()};
	REQUIRE(in >> plain);
	CHECK(plain == data_endpoint{"data1.example.org", 18203, key, {}, {}});

	data_endpoint labelled;
	std::istringstream with_region{"[::1]:4711/" + key.in_hex() + "/eu-north"};
	REQUIRE(with_region >> labelled);
	CHECK(labelled == data_endpoint{"::1", 4711, key, "eu-north", {}});

	std::ostringstream out;
	out << labelled;
	data_endpoint again;
	std::istringstream round_trip{out.str()};
	REQUIRE(round_trip >> again);
	CHECK(again == labelled);

	data_endpoint bad;
	std::istringstream no_key{"host:18203"};
	CHECK(!(no_key >> bad));
	std::istringstream no_port{"host/" + key.in_hex()};
	CHECK(!(no_port >> bad));
}

// (RDS 9) a release goes out in packets of a bounded number of ids
TEST_CASE("release packets", "[unit]") {
	auto const sid = securepath::test::random_octet_vector(16);
	std::vector<data_id> ids;
	for(int i = 0; i != 1201; ++i) {
		ids.push_back(securepath::test::random_octet_vector(64));
	}

	CHECK(release_packets(sid, {}).empty());

	auto const one = release_packets(sid, {ids.front()});
	REQUIRE(one.size() == 1);
	CHECK(one.front().sid == sid);
	CHECK(one.front().data_ids == std::vector<data_id>{ids.front()});

	auto const packets = release_packets(sid, ids);
	REQUIRE(packets.size() == 3);
	CHECK(packets.at(0).data_ids.size() == release_batch_size);
	CHECK(packets.at(1).data_ids.size() == release_batch_size);
	CHECK(packets.at(2).data_ids.size() == 201);
	// every id once, in order
	std::vector<data_id> all;
	for(auto const& p : packets) {
		CHECK(p.sid == sid);
		all.insert(all.end(), p.data_ids.begin(), p.data_ids.end());
	}
	CHECK(all == ids);

	// an exact multiple has no empty tail, a batch of nothing is a batch of one
	CHECK(release_packets(sid, std::vector<data_id>(ids.begin(), ids.begin() + 1000)).size() == 2);
	CHECK(release_packets(sid, std::vector<data_id>(ids.begin(), ids.begin() + 3), 0).size() == 3);
}

// (RDS 10) the same batching for the copies a data server is told to get
TEST_CASE("replicate packets", "[unit]") {
	auto const sid = securepath::test::random_octet_vector(16);
	std::vector<data_descriptor> descriptors;
	for(int i = 0; i != 501; ++i) {
		descriptors.push_back(test_descriptor());
	}
	CHECK(replicate_packets(sid, {}).empty());
	auto const packets = replicate_packets(sid, descriptors);
	REQUIRE(packets.size() == 2);
	CHECK(packets[0].sid == sid);
	CHECK(packets[0].descriptors.size() == release_batch_size);
	CHECK(packets[1].descriptors == std::vector<data_descriptor>{descriptors.back()});
	CHECK(in_batches(std::vector<int>{1, 2, 3, 4, 5}, 2) == std::vector<std::vector<int>>{{1, 2}, {3, 4}, {5}});
}

namespace {

/// the server holds the whole data of ten chunks
data_holding complete(data_endpoint const& e) {
	return data_holding{e.key, 10, 10, true};
}

/// the server holds four chunks of ten
data_holding partial(data_endpoint const& e) {
	return data_holding{e.key, 4, 10, false};
}

}

// RD13 copy count: the first k servers of the placement order are to hold the data
TEST_CASE("data copy count", "[unit]") {
	auto const endpoints = make_endpoints(4);
	auto const id = securepath::test::random_octet_vector(64);
	auto const sid = securepath::test::random_octet_vector(16);
	auto const placement = upload_order(endpoints, id);

	SECTION("the copies missing") {
		// nobody holds it completely: nowhere to get it from yet
		CHECK(missing_copies(endpoints, id, {}, 2).empty());
		CHECK(missing_copies(endpoints, id, {partial(placement[0])}, 2).empty());

		// the uploader's first choice has it: the second primary is missing
		CHECK(missing_copies(endpoints, id, {complete(placement[0])}, 1).empty());
		CHECK(missing_copies(endpoints, id, {complete(placement[0])}, 2) == std::vector<data_endpoint>{placement[1]});
		CHECK(missing_copies(endpoints, id, {complete(placement[0])}, 3) == std::vector<data_endpoint>{placement[1], placement[2]});
		// a part is no copy
		CHECK(missing_copies(endpoints, id, {complete(placement[0]), partial(placement[1])}, 2) == std::vector<data_endpoint>{placement[1]});
		CHECK(missing_copies(endpoints, id, {complete(placement[0]), complete(placement[1])}, 2).empty());
		// the upload fell back to a server that is no primary: the primaries still get theirs
		CHECK(missing_copies(endpoints, id, {complete(placement[3])}, 2) == std::vector<data_endpoint>{placement[0], placement[1]});
		// more copies than servers: everybody
		CHECK(missing_copies(endpoints, id, {complete(placement[2])}, 9) == std::vector<data_endpoint>{placement[0], placement[1], placement[3]});
		// a holder that is no data server of the storage is nowhere to get it from
		CHECK(missing_copies(endpoints, id, {data_holding{crypto::public_key_id{securepath::test::random_octet_vector(32)}, 10, 10, true}}, 2).empty());
	}

	SECTION("where a copy comes from") {
		// the complete holders in download order, not the asker
		data_availability table;
		table.set_load(placement[0].key, holder_load{100, 5});
		table.set_load(placement[2].key, holder_load{100, 0});
		std::vector<data_holding> const holdings{complete(placement[0]), partial(placement[1]), complete(placement[2])};
		CHECK(replica_sources(endpoints, id, holdings, table, placement[1].key) == std::vector<data_endpoint>{placement[2], placement[0]});
		CHECK(replica_sources(endpoints, id, holdings, table, placement[2].key) == std::vector<data_endpoint>{placement[0]});
		CHECK(replica_sources(endpoints, id, {partial(placement[0])}, table, placement[1].key).empty());
	}

	SECTION("what the table knows") {
		// the sweep goes over what somebody announced
		data_availability table;
		CHECK(table.known_data().empty());
		table.announce(sid, id, complete(placement[0]));
		table.announce(sid, id, complete(placement[1]));
		CHECK(table.known_data() == std::vector<std::pair<protocol::storage_id, data_id>>{{sid, id}});
		table.forget(sid, id);
		CHECK(table.known_data().empty());

		// a holder that tells everything anew: what it said before is void
		auto const other = securepath::test::random_octet_vector(64);
		table.announce(sid, id, complete(placement[0]));
		table.announce(sid, id, complete(placement[1]));
		table.announce(sid, other, complete(placement[0]));
		table.forget_holder(placement[0].key);
		CHECK(table.holdings(sid, id) == std::vector<data_holding>{complete(placement[1])});
		CHECK(table.holdings(sid, other).empty());
		CHECK(table.known_data() == std::vector<std::pair<protocol::storage_id, data_id>>{{sid, id}});
	}
}

// (RDS 10) the ticket of a pull: for data servers only, never for the asking
TEST_CASE("replica ticket issuer", "[unit]") {
	auto const server_key = crypto::generate_private_key();
	crypto::public_key_cache keys;
	keys.insert(server_key.public_key());
	auto const sid = securepath::test::random_octet_vector(16);
	auto const descriptor = test_descriptor();
	auto const& id = descriptor.manifest_digest;
	auto const now = clock_type::now();
	auto const endpoints = make_endpoints(3);
	auto const placement = upload_order(endpoints, id);
	data_availability table;
	ticket_issuer issuer{endpoints, table, 600s};

	// a member cannot ask for the right
	auto const member = crypto::public_key_id{securepath::test::random_octet_vector(32)};
	CHECK(is_error(issuer.issue(sid, descriptor, member, static_cast<std::uint32_t>(data_right::replicate), server_key, now)
		, protocol::errc::invalid_state));
	// and is no data server
	table.announce(sid, id, data_holding{placement[0].key, 3, 3, true});
	CHECK(is_error(issuer.issue_replica(sid, descriptor, member, server_key, now), protocol::errc::invalid_state));

	auto const issued = issuer.issue_replica(sid, descriptor, placement[1].key, server_key, now);
	REQUIRE(issued);
	CHECK(issued->ticket.right() == data_right::replicate);
	CHECK(issued->ticket.member() == placement[1].key);
	CHECK(issued->ticket.descriptor() == descriptor);
	CHECK(issued->ticket.storage_id() == sid);
	CHECK(!issued->ticket.verify(keys, now));
	CHECK(issued->holders == std::vector<data_endpoint>{placement[0]});

	// nothing to pull from, nothing the storage vouches for, nothing to sign with
	CHECK(is_error(issuer.issue_replica(sid, descriptor, placement[0].key, server_key, now), protocol::errc::data_not_held));
	CHECK(is_error(issuer.issue_replica(sid, make_error(protocol::errc::data_pruned), placement[1].key, server_key, now), protocol::errc::data_pruned));
	CHECK(is_error(issuer.issue_replica(sid, make_error(protocol::errc::unknown_data), placement[1].key, server_key, now), protocol::errc::unknown_data));
	CHECK(is_error(issuer.issue_replica(sid, descriptor, placement[1].key, std::nullopt, now), protocol::errc::invalid_state));
}

namespace {

/// a record server's view of the copies without the servers around it: three data
/// servers, all reachable, copy count 2, one storage whose standings the test sets
struct plan_scene {
	plan_scene() {
		for(auto const& e : endpoints) {
			reachable.insert(e.key);
		}
	}

	/// a data a record of the storage names
	data_descriptor named() {
		auto const d = test_descriptor();
		standings[d.manifest_digest] = data_standing{d, false};
		return d;
	}

	/// a data of a version the storage let go
	data_descriptor pruned() {
		auto const d = test_descriptor();
		standings[d.manifest_digest] = data_standing{std::nullopt, true};
		return d;
	}

	/// a data no record here names
	data_descriptor unknown() {
		auto const d = test_descriptor();
		standings[d.manifest_digest] = data_standing{};
		return d;
	}

	/// the server in the place of the data's placement order announced it, whole or a third
	crypto::public_key_id held_by(data_descriptor const& d, std::size_t place, bool complete = true) {
		auto const holder = upload_order(endpoints, d.manifest_digest)[place].key;
		table.announce(sid, d.manifest_digest, data_holding{holder, complete ? 3u : 1u, 3, complete});
		return holder;
	}

	crypto::public_key_id second_of(data_descriptor const& d) const {
		return upload_order(endpoints, d.manifest_digest)[1].key;
	}

public:
	std::vector<data_endpoint> const endpoints{make_endpoints(3)};
	protocol::storage_id const sid{securepath::test::random_octet_vector(16)};
	data_availability table;
	std::map<data_id, data_standing> standings;
	std::set<crypto::public_key_id> reachable;
	std::vector<data_id> asked;
	replication_view const view{endpoints, table, 2
		, [this](crypto::public_key_id const& key) { return reachable.contains(key); }
		, [this](protocol::storage_id const&, data_id const& id) {
			asked.push_back(id);
			return standings[id];
		}};
};

}

// (RDS 10) what a record server does about the copies, without the servers around it
TEST_CASE("replication plan", "[unit]") {
	plan_scene s;
	auto const wanted = s.named(), copied = s.named(), uploading = s.named();
	auto const pruned = s.pruned(), unknown = s.unknown();
	s.held_by(wanted, 0);
	s.held_by(copied, 0);
	s.held_by(copied, 1);
	s.held_by(uploading, 0, false);
	s.held_by(pruned, 0);
	s.held_by(unknown, 0);

	auto const plan = plan_replication(s.view, s.table.known_data());
	// the second primary of the wanted data gets a copy; nothing for what has its copies,
	// is still coming in, or may be a record that has not arrived here yet
	REQUIRE(plan.copies.size() == 1);
	REQUIRE(plan.copies.contains(s.second_of(wanted)));
	CHECK(plan.copies.at(s.second_of(wanted)).at(s.sid) == std::vector<data_descriptor>{wanted});
	// what the storage certainly let go is released where it is held
	REQUIRE(plan.stale.size() == 1);
	CHECK(plan.stale.at(s.sid) == std::vector<data_id>{pruned.manifest_digest});
	// the storage is not asked about what nobody holds completely
	CHECK(std::ranges::find(s.asked, uploading.manifest_digest) == s.asked.end());
	CHECK(s.asked.size() == 4);

	// a data server that cannot be told now is left for the next sweep
	s.reachable.erase(s.second_of(wanted));
	CHECK(plan_replication(s.view, s.table.known_data()).copies.empty());
	CHECK(plan_replication(s.view, {}).empty());
}

}
