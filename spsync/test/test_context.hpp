#ifndef SPSYNC_TEST_TEST_CONTEXT_HEADER
#define SPSYNC_TEST_TEST_CONTEXT_HEADER

#include <securepath/network/encryption/context.hpp>
#include <securepath/network/test_data/ssl_test_data.hpp>
#include <securepath/crypto/certificate_cache.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/shared_secret_cache.hpp>
#include <securepath/crypto/private_data_cache.hpp>
#include <securepath/crypto/test/support/pki_test_context.hpp>
#include <securepath/crypto/test/support/public_key_test_cache.hpp>

namespace securepath::sync::test {

/**
 * Testing context that holds context for server and for n clients
 **/
class test_context {
public:
	test_context(int threads = 2);
	~test_context();

	void add_client(int amount = 1);

	network::context& client_context(int n);
	network::context& server_context();

	void add_client_keys_for_server();
	void share_client_keys();

	crypto::public_key_id key_id(int n) const;
private:
  std::vector<std::thread> threads;
	asio::io_context io;
	asio::ssl::context client_ssl{asio::ssl::context::tls_client};
	asio::ssl::context server_ssl{asio::ssl::context::tls_server};

	crypto::test::pki_test_context pki_context;

	struct instance {
		instance(asio::io_context& io, asio::ssl::context& ssl, crypto::public_key root_key)
		: keys{root_key}
		, context{io, ssl, keys, certs, shared_secret, private_data}
		{}

		crypto::certificate_cache certs;
		crypto::test::public_key_test_cache keys;
		crypto::shared_secret_cache shared_secret;
		crypto::private_data_cache private_data;
		network::context context;
	};

	std::deque<std::unique_ptr<instance>> clients;
	instance server{io, server_ssl, pki_context.root.public_key()};

	asio::executor_work_guard<asio::io_context::executor_type> io_guard{io.get_executor()};
};

}

#endif