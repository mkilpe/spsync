#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/server/server_lib/data_availability.hpp>
#include <spsync/server/server_lib/peer_config.hpp>
#include <spsync/server/server_lib/ticket_issuer.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>

#include <algorithm>
#include <map>
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

data_descriptor test_descriptor() {
	return data_descriptor{3 * 1024 * 1024, 1024 * 1024, securepath::test::random_octet_vector(64)};
}

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

	auto const is_error = [](util::result<issued_ticket> const& r, protocol::errc code) {
		return !r && r.get_error().code() == make_error_code(code);
	};

	CHECK(is_error(issuer.issue(sid, std::nullopt, member, upload, server_key, now), protocol::errc::unknown_data));
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

}
