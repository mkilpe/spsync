#pragma once

#include "data_channel.hpp"

#include <spsync/core/data/data_ticket.hpp>

#include <securepath/network/encryption/context.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <vector>

namespace securepath::sync {

/**
 * What a record server grants for a data (record_data.txt RD12/RD13): the signed ticket
 * and the data servers to use it at, in the order to try them. The list is the record
 * server's load balancing decision and transient: a new grant gives the current view.
 */
struct data_grant {
	data_ticket ticket;
	std::vector<data_endpoint> holders;
};

/**
 * Asks the storage's record server for a grant. Answered exactly once through the
 * callback, from any thread and possibly before the call returns. The implementation
 * over the record server connection comes with the ticket issuing (RDS 5).
 */
using ticket_source = std::function<void(data_descriptor const&, data_right
	, std::move_only_function<void(util::result<data_grant>)>)>;

/**
 * The data channels over the network (RD12: clients move data directly with the data
 * servers). A transfer is opened with a fresh grant at the first holder that can be
 * reached - a holder that is down is the next entry (RD13), and so is, for a download,
 * one that does not hold the data; any other refusal by a holder is the answer. Connections are made on demand, one per data server, and
 * shared by the uploads going there; the server must authenticate with the key the
 * grant names. A lost connection answers the calls still out on it with an error.
 */
class net_data_channel : public data_channel, public data_download_channel {
public:
	net_data_channel(network::context&, ticket_source, std::chrono::seconds timeout = std::chrono::seconds{10});
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
