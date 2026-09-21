#pragma once

#include <spsync/core/data/data_descriptor.hpp>

#include <asio/io_context.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>

namespace securepath::sync {

struct transfer_retry_config {
	/// the wait before the first retry of a data; doubled for every further one
	std::chrono::milliseconds first{1000};

	/// the longest wait between two tries
	std::chrono::milliseconds max{60000};
};

/**
 * True for a transfer that ended with an error another try may lift without anybody
 * doing anything: a lost data connection, a data server that could not be reached, an
 * expired ticket, a transfer quota window, a full data server. False for what another
 * try would only repeat (a ticket that is refused, a manifest or chunk that does not
 * verify, a data nobody knows, no data servers) and for data_not_held, which is news for
 * the owner (remote_not_complete) and ends with a notification, not with a timer.
 */
bool retryable_transfer_error(error const&);

/**
 * Tries ended transfers again after a wait (record_data.txt RDS 7): a transfer that lost
 * its data connection must not wait for the record connection to drop too. The wait is
 * what the error says (a transfer quota's retry after) or the data's backoff, which
 * grows with every try until the data is forgotten - its transfer ended for good.
 *
 * Thread safe; the retry function is called on an io thread.
 */
class transfer_retry {
public:
	transfer_retry(asio::io_context&, transfer_retry_config, std::function<void(data_id const&)> retry);
	~transfer_retry();

	/// another try of the data after the hint, or after its backoff
	void schedule(data_id const&, std::optional<std::chrono::seconds> hint = {});

	/// the data's transfer ended for good: its backoff starts over next time
	void forget(data_id const&);

	/// drop every wait and backoff (the record connection went: the owner asks again)
	void cancel();

	/// datas waiting for their next try
	std::size_t waiting() const;

private:
	class impl;
	std::shared_ptr<impl> impl_;
};

}
