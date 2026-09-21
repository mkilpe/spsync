#include "ticket_issuer.hpp"

#include <spsync/protocol/error.hpp>

namespace securepath::sync {

ticket_issuer::ticket_issuer(std::vector<data_endpoint> data_servers, data_availability const& availability, std::chrono::seconds validity)
: data_servers_(std::move(data_servers))
, availability_(availability)
, validity_(validity)
{
}

util::result<issued_ticket> ticket_issuer::issue(protocol::storage_id const& sid, util::result<data_descriptor> const& committed
	, crypto::public_key_id const& member, std::uint32_t right
	, std::optional<crypto::private_key> const& server_key, time_point now) const {
	util::result<issued_ticket> ret;
	bool const upload = right == static_cast<std::uint32_t>(data_right::upload);
	bool const download = right == static_cast<std::uint32_t>(data_right::download);
	if(!upload && !download) {
		ret = make_error(protocol::errc::invalid_state, "not a data right");
	} else if(!server_key) {
		ret = make_error(protocol::errc::invalid_state, "the record server has no key to sign tickets with");
	} else if(data_servers_.empty()) {
		ret = make_error(protocol::errc::no_data_servers);
	} else if(!committed) {
		ret = committed.get_error();
	} else {
		issued_ticket issued;
		issued.ticket = data_ticket{sid, committed.value(), member, static_cast<data_right>(right), now + validity_};
		issued.ticket.sign(*server_key);
		auto const& id = committed.value().manifest_digest;
		issued.holders = upload ? upload_order(data_servers_, id)
			: download_order(data_servers_, id, availability_.holdings(sid, id), availability_);
		ret = std::move(issued);
	}
	return ret;
}

}
