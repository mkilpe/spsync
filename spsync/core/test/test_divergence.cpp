// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/core/divergence.hpp>

#include <algorithm>
#include <functional>
#include <limits>
#include <map>

namespace securepath::sync {
namespace {

/// a history as the hashes by sequence; the lookup a log would answer
using history = std::map<std::uint64_t, octet_vector>;

held_hash holding(history const& h) {
	return [&h](sequence_number seq) {
		auto it = h.find(seq.value);
		return it == h.end() ? octet_vector{} : it->second;
	};
}

/// count records whose hashes name the sequence, forked from `fork_at` on when set
history make_history(std::uint64_t count, std::uint64_t fork_at = 0) {
	history ret;
	for(std::uint64_t seq = 1; seq <= count; ++seq) {
		auto const forked = fork_at != 0 && seq >= fork_at;
		ret[seq] = to_octet_vector(std::to_string(seq) + (forked ? "'" : ""));
	}
	return ret;
}

/// the samples a server with the history announces
std::vector<chain_block_id> samples_of(history const& h) {
	std::vector<chain_block_id> ret;
	if(!h.empty()) {
		for(auto const seq : sample_sequences(sequence_number{h.rbegin()->first})) {
			ret.push_back(chain_block_id{seq, h.at(seq.value)});
		}
	}
	return ret;
}

std::vector<std::uint64_t> values(std::vector<sequence_number> const& seqs) {
	std::vector<std::uint64_t> ret;
	for(auto const& s : seqs) {
		ret.push_back(s.value);
	}
	return ret;
}

}

// (plan 5.3) the head, 1, 2, 4, ... behind it and the first record
TEST_CASE("divergence sample sequences", "[unit]") {
	CHECK(sample_sequences({}).empty());
	CHECK(values(sample_sequences(sequence_number{1})) == std::vector<std::uint64_t>{1});
	CHECK(values(sample_sequences(sequence_number{2})) == std::vector<std::uint64_t>{2, 1});
	CHECK(values(sample_sequences(sequence_number{3})) == std::vector<std::uint64_t>{3, 2, 1});
	CHECK(values(sample_sequences(sequence_number{5})) == std::vector<std::uint64_t>{5, 4, 3, 1});
	CHECK(values(sample_sequences(sequence_number{1000}))
		== std::vector<std::uint64_t>{1000, 999, 998, 996, 992, 984, 968, 936, 872, 744, 488, 1});

	// about log2(head) of them however long the history
	auto const big = sample_sequences(sequence_number{std::uint64_t{1} << 40});
	CHECK(big.size() == 42);
	CHECK(big.front() == sequence_number{std::uint64_t{1} << 40});
	CHECK(big.back() == sequence_number{1});
	// a head at the top of the range does not wrap the distances
	auto const top = sample_sequences(sequence_number{std::numeric_limits<std::uint64_t>::max()});
	CHECK(top.size() == 65);
	CHECK(top.back() == sequence_number{1});
	CHECK(std::ranges::is_sorted(top, std::greater<>{}));
}

// (plan 5.3) where a peer's samples part from a history: the bound the samples give
TEST_CASE("divergence between histories", "[unit]") {
	auto const ours = make_history(5);

	SECTION("the same history") {
		CHECK(find_divergence(samples_of(ours), holding(ours)) == divergence{sequence_number{5}, {}});
		CHECK(!find_divergence(samples_of(ours), holding(ours)).diverged());
	}
	SECTION("a peer ahead is not divergence, we are only behind") {
		auto const theirs = make_history(9);
		CHECK(find_divergence(samples_of(theirs), holding(ours)) == divergence{sequence_number{5}, {}});
	}
	SECTION("a peer behind agrees as far as it goes") {
		auto const theirs = make_history(3);
		CHECK(find_divergence(samples_of(theirs), holding(ours)) == divergence{sequence_number{3}, {}});
	}
	SECTION("a fork the samples pin down") {
		auto const theirs = make_history(5, 4);
		auto const div = find_divergence(samples_of(theirs), holding(ours));
		CHECK(div == divergence{sequence_number{3}, sequence_number{4}});
		CHECK(div.exact());
		// seen from the other side alike
		CHECK(find_divergence(samples_of(ours), holding(theirs)) == div);
	}
	SECTION("a fork between two samples") {
		auto const long_ours = make_history(1000);
		auto const theirs = make_history(1000, 600);
		auto const div = find_divergence(samples_of(theirs), holding(long_ours));
		CHECK(div == divergence{sequence_number{488}, sequence_number{744}});
		CHECK(!div.exact());
		// samples in between narrow it down
		std::vector<chain_block_id> const between{{sequence_number{600}, theirs.at(600)}, {sequence_number{599}, theirs.at(599)}};
		CHECK(find_divergence(between, holding(long_ours)) == divergence{sequence_number{599}, sequence_number{600}});
	}
	SECTION("nothing in common") {
		auto const theirs = make_history(5, 1);
		auto const div = find_divergence(samples_of(theirs), holding(ours));
		CHECK(div == divergence{{}, sequence_number{1}});
		CHECK(div.exact());
	}
	SECTION("samples of records we do not hold say nothing") {
		auto const theirs = make_history(5, 4);
		CHECK(find_divergence(samples_of(theirs), holding(history{})) == divergence{});
		CHECK(find_divergence({}, holding(ours)) == divergence{});
	}
}

// (plan 4.4 with 5.3) the pull after what is held, none over a fork
TEST_CASE("divergence pull plan", "[unit]") {
	divergence const agree{sequence_number{3}, {}};
	CHECK(plan_pull(sequence_number{3}, sequence_number{5}, agree) == pull_range{sequence_number{4}, sequence_number{5}});
	// the newest common sample is further than the stored head: nothing held is pulled again
	CHECK(plan_pull(sequence_number{1}, sequence_number{5}, agree) == pull_range{sequence_number{4}, sequence_number{5}});
	// the stored head is further than the samples reach
	CHECK(plan_pull(sequence_number{4}, sequence_number{5}, agree) == pull_range{sequence_number{5}, sequence_number{5}});
	// nothing new
	CHECK(!plan_pull(sequence_number{5}, sequence_number{5}, agree).wanted());
	CHECK(!plan_pull(sequence_number{5}, {}, agree).wanted());
	// nothing held yet: from the first record
	CHECK(plan_pull({}, sequence_number{5}, {}) == pull_range{sequence_number{1}, sequence_number{5}});
	// a fork is not pulled: the records would conflict with held ones
	CHECK(!plan_pull(sequence_number{3}, sequence_number{5}, divergence{sequence_number{3}, sequence_number{4}}).wanted());
}

}
