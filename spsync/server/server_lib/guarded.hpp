#pragma once

#include <spsync/protocol/protocol_base.hpp>
#include <spsync/util/result.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <exception>

namespace securepath::sync {

/**
 * Work that answers a request and may throw - the store, the database, a key lookup -
 * with what escapes turned into the error the answer carries: a securepath::error as it
 * is, anything else as unknown_error, both logged with what was being done and for
 * which storage. The request is answered whatever happens. The work returns a
 * util::result, which an error converts to.
 */
template<typename Work>
auto guarded(char const* what, protocol::storage_id const& sid, Work work) -> decltype(work()) {
	try {
		return work();
	} catch(securepath::error const& err) {
		LOG_WARN("exception while {}: {} (sid={})", what, err, to_hex(sid));
		return err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while {}: {} (sid={})", what, ex.what(), to_hex(sid));
		return make_error(securepath::errc::unknown_error);
	}
}

}
