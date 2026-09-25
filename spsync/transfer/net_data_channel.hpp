// SPDX-License-Identifier: MIT

#pragma once

#include "data_channel.hpp"
#include <spsync/core/data/data_grant.hpp>

#include <spsync/core/data/data_ticket.hpp>

#include <securepath/network/encryption/context.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <vector>

namespace securepath::sync {

/**
 * The data channels over the network (RD12: clients move data directly with the data
 * servers). A transfer is opened with a fresh grant at the first holder that can be
 * reached - a holder that is down is the next entry (RD13), and so is, for a download,
 * one that does not hold the data; any other refusal by a holder is the answer. Connections are made on demand, one per data server, and
 * shared by the uploads going there; the server must authenticate with the key the
 * grant names. A lost connection answers the calls still out on it with an error, and so
 * does one that says nothing for the silence limit. close() lets the connections go on
 * their own strands and returns at once: the calls still out are answered shortly after.
 */
class net_data_channel : public data_channel, public data_download_channel {
public:
	/**
	 * timeout: connecting and the handshake. silence_limit: how long a data server may
	 * say nothing while calls are out, and how long the record server may take to answer
	 * a ticket request, before the transfer ends with a timeout (a path that died
	 * without a word would otherwise leave it "on its way" for good).
	 */
	net_data_channel(network::context&, ticket_source, std::chrono::seconds timeout = std::chrono::seconds{10}
		, std::chrono::seconds silence_limit = std::chrono::seconds{60});
	~net_data_channel();

	void open_upload(data_descriptor const&, data_manifest const&, open_callback) override;
	void send_piece(data_id const&, std::uint64_t chunk_no, std::uint64_t offset, octet_vector bytes, piece_callback) override;

	void open_download(data_descriptor const&, download_callback) override;
	void fetch_piece(data_id const&, std::uint64_t chunk_no, std::uint64_t offset, std::uint32_t size, fetch_callback) override;

	/// drop every data connection; the calls still out are answered with an error
	void close();

private:
	class impl;
	std::shared_ptr<impl> impl_;
};

}
