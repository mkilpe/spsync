// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/data/data_descriptor.hpp>
#include <spsync/core/data/data_ticket.hpp>
#include <spsync/util/result.hpp>

#include <functional>
#include <vector>
#include <spsync/util/move_only_function.hpp>

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
	, move_only_function<void(util::result<data_grant>)>)>;

}
