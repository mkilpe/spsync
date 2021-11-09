#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/request_storage.hpp>
#include <spsync/test/util.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/crypto/rsa.hpp>

namespace securepath::sync::client::test {

TEST_CASE("request_storage test", "[unit]") {
	request_storage storage(sync::test::create_test_database("test_req_storage.db"));

	auto priv_key = crypto::generate_rsa_private_key(1024);

	crypto::public_key_id t1{to_octet_vector("test1")};
	crypto::public_key_id t2{to_octet_vector("test2")};

	request_data rdata{user{t1, host_port{}}, "test tag", securepath::test::random_octet_vector(8)};
	packet_transport::transport_payload tpay{};
	tpay.signature = priv_key.sign(serialisation::asn_der_serialise(tpay.data));

	CHECK(storage.enumerate().size() == 0);
	CHECK(!storage.find(1));

	auto h1 = storage.add(rdata, tpay);
	CHECK(storage.enumerate().size() == 1);
	CHECK(storage.enumerate(request_state::waiting_for_verification).size() == 1);
	CHECK(storage.enumerate(request_state::verification_succeeded).size() == 0);
	auto r = storage.find(h1);
	REQUIRE(r);
	CHECK(rdata.sender == r->sender);
	CHECK(rdata.tag == r->tag);
	CHECK(rdata.data == r->data);
	CHECK(r->id == h1);
	CHECK(r->state == request_state::waiting_for_verification);
	CHECK(priv_key.public_key().verify(r->payload.signature, serialisation::asn_der_serialise(r->payload.data)));

	auto h2 = storage.add(rdata, tpay);
	CHECK(storage.enumerate().size() == 2);
	storage.change_state(h1, request_state::verification_succeeded);
	CHECK(storage.enumerate(request_state::waiting_for_verification).size() == 1);
	CHECK(storage.enumerate(request_state::verification_succeeded).size() == 1);

	storage.remove(h1);
	CHECK(storage.enumerate().size() == 1);
	CHECK(storage.enumerate(request_state::waiting_for_verification).size() == 1);
	CHECK(storage.enumerate(request_state::verification_succeeded).size() == 0);

	CHECK(!storage.is_sender_banned(t1));
	CHECK(!storage.is_sender_banned(t2));
	storage.ban_sender(t1);
	CHECK(storage.is_sender_banned(t1));
	CHECK(!storage.is_sender_banned(t2));
}

}
