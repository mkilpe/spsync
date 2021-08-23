#include "test_context.hpp"

#include <securepath/crypto/rsa.hpp>

#include <securepath/network/encryption/handshake/dh_handshake.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>

namespace securepath::sync::test {

test_context::test_context(int count)
{
	for(int i = 0; i != count; ++i) {
		threads.emplace_back(
			[&]{
				io.run();
			});
	}

	auto server_key = crypto::generate_rsa_private_key(1024);
	server.private_data.set_my_private_key(server_key);
	server.private_data.set_my_certificate_chain(pki_context.chain_for_server_key(server_key, {}));
	enable_server_dh_handshake(server.context);
	enable_server_pk_handshake(server.context);
}

test_context::~test_context() {
	io_guard.reset();
	for(auto& t : threads) {
		t.join();
	}
}

void test_context::add_client(int amount) {
	for(int i = 0; i != amount; ++i) {
		clients.push_back(std::make_unique<instance>(io, client_ssl, pki_context.root.public_key()));
		auto priv_key = crypto::generate_rsa_private_key(1024);
		clients.back()->private_data.set_my_private_key(priv_key);
		clients.back()->keys.insert(priv_key.public_key());
		enable_client_dh_handshake(clients.back()->context);
		enable_client_pk_handshake(clients.back()->context);
	}
}

network::context& test_context::client_context(int n) {
	assert(n < clients.size());
	return clients[n]->context;
}

network::context& test_context::server_context() {
	return server.context;
}

void test_context::add_client_keys_for_server() {
	for(auto&& v : clients) {
		server.keys.insert(my_private_key(v->private_data).public_key());
	}
}

}