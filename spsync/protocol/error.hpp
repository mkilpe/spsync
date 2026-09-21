#pragma once

#include <securepath/util/error.hpp>
#include <securepath/network/net_error.hpp>

#include <chrono>
#include <cstdint>
#include <optional>

namespace securepath::sync::protocol {
inline namespace v1 {

enum class errc {
	no_error = 0,
	no_such_storage,
	record_already_committed,
	invalid_record,
	conflicting_record,
	record_out_of_sync,
	invalid_client_key,
	invalid_state,
	storage_mode_mismatch,
	unknown_signer,
	invalid_storage_modes,
	/// the replica is still catching up with its peers (bootstrap, plan 5.2): try another one
	storage_syncing,
	/// the record content exceeds the storage's max_record_size (record_data.txt RD10)
	record_too_big,
	/// the data ticket is not one this data server accepts: unsigned, forged, unknown or
	/// untrusted issuer, another member's, the wrong right (record_data.txt RD12)
	invalid_data_ticket,
	/// the data ticket has expired: ask the record server for a new one
	data_ticket_expired,
	/// the manifest is not the one the descriptor commits to
	invalid_data_manifest,
	/// the chunk is not the one the manifest names at that position
	invalid_data_chunk,
	/// a chunk for a data no manifest opened on this connection
	no_such_upload,
	/// the data server's storage quota does not allow the data now (RD10: availability,
	/// never validity - the record stays valid, another holder or a later try may take it)
	data_quota_exceeded,
	/// the data is bigger than this data server takes (RD10)
	data_too_big,
	/// no committed record of the storage names the data: no ticket for it (RD12)
	unknown_data,
	/// the storage has no data-role servers configured: it carries no record data
	no_data_servers,
	/// the data server does not hold what was asked for: the data, or that chunk of it
	/// (an upload still in progress, RD7 remote_not_complete) - another holder may
	data_not_held,
	/// the data server's transfer quota for the storage is used up for this window
	/// (RD10): what was fetched is kept, the rest goes on in a later window
	data_transfer_quota_exceeded,
	end_of_list
};

}

std::error_condition make_error_condition(errc e);
std::error_code make_error_code(errc e);
std::error_category const& error_category();

/// convert net_error to error using the errc from this protocol
error to_error(network::net_error const& err);

/**
 * An error that says when another try makes sense (a transfer quota window, RD10): the
 * seconds travel in the error's message, so they survive every layer an error passes.
 */
error make_retry_error(errc, std::uint32_t retry_after_seconds);

/// the seconds of make_retry_error; nullopt for any other error
std::optional<std::chrono::seconds> retry_after(error const&);

}

namespace std {

	template<>
	struct is_error_condition_enum<securepath::sync::protocol::errc>
		: public true_type {};
	template<>
	struct is_error_code_enum<securepath::sync::protocol::errc>
		: public true_type {};
}

