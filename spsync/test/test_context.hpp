#pragma once

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/private_data_access.hpp>
#include <securepath/crypto/public_key_access.hpp>
#include <securepath/network/encryption/context.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>
#include <securepath/network/test/network_test_context.hpp>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <cassert>
#include <deque>
#include <memory>
#include <thread>
#include <vector>

namespace securepath::sync::test {

/**
 * Testing context that holds a network context for a server and for n clients, all sharing one
 * test PKI root. Replaces the old sp network::test::test_context (dh handshake is gone, the
 * anonymous pk client covers that use; keys are PQ suite keys).
 */
class test_context {
public:
	explicit test_context(int threads = 2)
	{
		init(threads);
	}

	test_context(crypto::private_key const& root, int threads = 2)
	: pki_(root)
	{
		init(threads);
	}

	~test_context() {
		guard_.reset();
		io_.stop();
		for(auto& t : threads_) {
			t.join();
		}
	}

	test_context(test_context const&) = delete;
	test_context& operator=(test_context const&) = delete;

	void add_client(int amount = 1) {
		for(int i = 0; i != amount; ++i) {
			clients_.push_back(std::make_unique<endpoint>(io_, pki_.root.public_key()));
			auto priv_key = crypto::generate_private_key();
			clients_.back()->state.private_data.set_my_private_key(priv_key);
			clients_.back()->state.private_data.set_my_certificate_chain(pki_.chain_for_server_key(priv_key, {}));
			clients_.back()->state.keys.insert(priv_key.public_key());
			network::enable_client_pk_handshake(clients_.back()->context);
		}
	}

	network::context& client_context(std::size_t n) {
		assert(n < clients_.size());
		return clients_[n]->context;
	}

	network::context& server_context() {
		return server_.context;
	}

	void add_client_keys_for_server() {
		for(auto&& v : clients_) {
			server_.state.keys.insert(crypto::my_private_key(v->state.private_data).public_key());
		}
	}

	void share_client_keys() {
		for(auto&& v1 : clients_) {
			for(auto&& v2 : clients_) {
				v1->state.keys.insert(crypto::my_private_key(v2->state.private_data).public_key());
			}
		}
	}

	crypto::public_key_id key_id(std::size_t n) const {
		assert(n < clients_.size());
		return crypto::my_private_key(clients_[n]->state.private_data).public_key().id();
	}

	crypto::private_key root_key() const {
		return pki_.root;
	}

private:
	struct endpoint {
		endpoint(asio::io_context& io, crypto::public_key const& root)
		: state(root)
		, context(io, state.keys, state.certs, state.secrets, state.private_data)
		{}

		network::test::endpoint_state state;
		network::context context;
	};

	void init(int threads) {
		for(int i = 0; i != threads; ++i) {
			threads_.emplace_back([this]{ io_.run(); });
		}

		auto server_key = crypto::generate_private_key();
		server_.state.private_data.set_my_private_key(server_key);
		server_.state.private_data.set_my_certificate_chain(pki_.chain_for_server_key(server_key, {}));
		network::enable_server_pk_handshake(server_.context);
	}

private:
	crypto::test::pki_test_context pki_;
	asio::io_context io_;
	asio::executor_work_guard<asio::io_context::executor_type> guard_{io_.get_executor()};

	endpoint server_{io_, pki_.root.public_key()};
	std::deque<std::unique_ptr<endpoint>> clients_;
	std::vector<std::thread> threads_;
};

}
