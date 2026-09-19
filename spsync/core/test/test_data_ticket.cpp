#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/core/data/data_ticket.hpp>

#include <securepath/crypto/error.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

data_descriptor test_descriptor() {
	return data_descriptor{5080, 1000, securepath::test::random_octet_vector(64)};
}

/// the wire form of a ticket with everything in reach
struct wire_ticket {
	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & storage_id & descriptor & member & right & expiry & signature & trailing_data;
	}

	octet_vector storage_id;
	data_descriptor descriptor;
	crypto::public_key_id member;
	std::uint32_t right{};
	time_point expiry;
	crypto::signature signature;
	serialisation::trailing_data trailing_data;
};

/// the ticket as it arrives when somebody changed it on the way, the signature kept
template<typename Change>
data_ticket tampered(data_ticket const& ticket, Change change) {
	auto wire = serialisation::asn_der_deserialise<wire_ticket>(serialisation::asn_der_serialise(ticket));
	change(wire);
	return serialisation::asn_der_deserialise<data_ticket>(serialisation::asn_der_serialise(wire));
}

}

// RD12: what a record server states about a data transfer, signed
TEST_CASE("data ticket", "[unit]") {
	auto const record_server = crypto::generate_private_key();
	auto const member = crypto::generate_private_key().id();
	crypto::public_key_cache keys;
	keys.insert(record_server.public_key());

	auto const now = clock_type::now();
	auto const sid = securepath::test::random_octet_vector(16);
	auto const descriptor = test_descriptor();
	data_ticket ticket{sid, descriptor, member, data_right::upload, now + 10min};

	CHECK(ticket.storage_id() == sid);
	CHECK(ticket.descriptor() == descriptor);
	CHECK(ticket.data() == descriptor.manifest_digest);
	CHECK(ticket.member() == member);
	CHECK(ticket.right() == data_right::upload);
	CHECK(!ticket.is_signed());
	CHECK(ticket.verify(keys, now).code() == make_error_code(securepath::errc::invalid_state));

	ticket.sign(record_server);
	CHECK(ticket.is_signed());
	CHECK(ticket.issuer() == record_server.id());
	CHECK(!ticket.verify(keys, now));

	SECTION("over the wire") {
		auto const copy = serialisation::asn_der_deserialise<data_ticket>(serialisation::asn_der_serialise(ticket));
		CHECK(copy.storage_id() == sid);
		CHECK(copy.descriptor() == descriptor);
		CHECK(copy.member() == member);
		CHECK(copy.right() == data_right::upload);
		CHECK(copy.issuer() == record_server.id());
		CHECK(!copy.verify(keys, now));
	}

	SECTION("expiry") {
		CHECK(!ticket.verify(keys, now + 9min));
		CHECK(ticket.verify(keys, now + 10min).code() == make_error_code(securepath::errc::timeout));
		CHECK(ticket.verify(keys, now + 1h).code() == make_error_code(securepath::errc::timeout));
	}

	SECTION("an issuer whose key is not known") {
		crypto::public_key_cache none;
		CHECK(ticket.verify(none, now).code() == make_error_code(crypto::errc::no_such_key));
	}

	SECTION("every stated field is signed") {
		CHECK(!tampered(ticket, [](wire_ticket&) {}).verify(keys, now));
		std::vector<data_ticket> const forged{
			tampered(ticket, [](wire_ticket& w) { w.storage_id[0] ^= 1; }),
			tampered(ticket, [](wire_ticket& w) { w.descriptor.manifest_digest[5] ^= 1; }),
			tampered(ticket, [](wire_ticket& w) { w.descriptor.enc_size += 1; }),
			tampered(ticket, [](wire_ticket& w) { w.descriptor.chunk_size = 2000; }),
			tampered(ticket, [](wire_ticket& w) { w.member = crypto::generate_private_key().id(); }),
			tampered(ticket, [](wire_ticket& w) { w.right = static_cast<std::uint32_t>(data_right::download); }),
			tampered(ticket, [](wire_ticket& w) { w.expiry += 1h; })};
		for(auto const& f : forged) {
			CHECK(f.verify(keys, now).code() == make_error_code(crypto::errc::signature_not_authentic));
		}

		// a ticket signed by somebody else verifies only as that somebody
		auto const intruder = crypto::generate_private_key();
		data_ticket other{sid, descriptor, member, data_right::upload, now + 10min};
		other.sign(intruder);
		CHECK(other.issuer() == intruder.id());
		CHECK(other.verify(keys, now).code() == make_error_code(crypto::errc::no_such_key));
	}
}

}
