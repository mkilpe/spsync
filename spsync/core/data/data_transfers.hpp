#pragma once

#include "data_descriptor.hpp"
#include "data_grant.hpp"

#include <securepath/util/error.hpp>

#include <functional>
#include <optional>

namespace securepath::sync {

/**
 * The record data transfers behind a storage connection (record_data.txt RD12): what
 * moves a data of the store to the storage's data servers and fetches one from them.
 * The record connection asks for the transfers, provides the tickets, tells when it
 * is up and hears how the transfers end; what is behind (data connections, pieces,
 * retries) is spsync/transfer's business, and a storage that keeps no record data
 * has no transfers at all. This is the seam between the two: neither knows the other.
 */
struct data_transfers {
	/// how a transfer ended: complete, or the error; a wait for another try is no end
	using done_callback = std::function<void(data_id const&, std::optional<error>)>;

	virtual ~data_transfers() = default;

	/**
	 * Wires the transfers to their record connection: the tickets are asked from the
	 * source, the ends reported through the callbacks - from any thread, possibly for
	 * a transfer on_disconnected already dropped, so the owner keeps its own books of
	 * what is on its way. Called once, before anything is queued.
	 */
	virtual void attach(ticket_source, done_callback upload_done, done_callback download_done) = 0;

	/// moves the data of the store to the storage's data servers; nothing for a data on its way
	virtual void upload(data_id const&) = 0;

	/// fetches the data from the storage's data servers into the store; nothing for a data on its way
	virtual void fetch(data_id const&) = 0;

	/// the record connection is up: tickets are answered, a transfer that ended may be tried again
	virtual void on_connected() = 0;

	/// the record connection went: the transfers on their way are dropped without a word,
	/// what was moved stays on both sides and the owner asks again after the reconnect
	virtual void on_disconnected() = 0;
};

}
