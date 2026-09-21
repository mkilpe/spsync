#include "ticket_issuer.hpp"

#include <spsync/protocol/error.hpp>

#include <algorithm>

namespace securepath::sync {

ticket_issuer::ticket_issuer(std::vector<data_endpoint> data_servers, data_availability const& availability, std::chrono::seconds validity)
: data_servers_(std::move(data_servers))
, availability_(availability)
, validity_(validity)
{
}

error ticket_issuer::refusal(util::result<data_descriptor> const& committed, std::optional<crypto::private_key> const& server_key) const {
	error ret;
	if(!server_key) {
		ret = make_error(protocol::errc::invalid_state, "the record server has no key to sign tickets with");
	} else if(data_servers_.empty()) {
		ret = make_error(protocol::errc::no_data_servers);
	} else if(!committed) {
		ret = committed.get_error();
	}
	return ret;
}

util::result<issued_ticket> ticket_issuer::issue(protocol::storage_id const& sid, util::result<data_descriptor> const& committed
	, crypto::public_key_id const& member, std::uint32_t right
	, std::optional<crypto::private_key> const& server_key, time_point now) const {
	util::result<issued_ticket> ret;
	bool const upload = right == static_cast<std::uint32_t>(data_right::upload);
	bool const download = right == static_cast<std::uint32_t>(data_right::download);
	if(!upload && !download) {
		// replicate included: that one is not for the asking
		ret = make_error(protocol::errc::invalid_state, "not a data right");
	} else if(auto const refused = refusal(committed, server_key)) {
		ret = refused;
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

util::result<issued_ticket> ticket_issuer::issue_replica(protocol::storage_id const& sid, util::result<data_descriptor> const& committed
	, crypto::public_key_id const& data_server
	, std::optional<crypto::private_key> const& server_key, time_point now) const {
	util::result<issued_ticket> ret;
	if(std::ranges::find(data_servers_, data_server, &data_endpoint::key) == data_servers_.end()) {
		ret = make_error(protocol::errc::invalid_state, "not a data server of this record server");
	} else if(auto const refused = refusal(committed, server_key)) {
		ret = refused;
	} else {
		issued_ticket issued;
		auto const& id = committed.value().manifest_digest;
		issued.holders = replica_sources(data_servers_, id, availability_.holdings(sid, id), availability_, data_server);
		if(issued.holders.empty()) {
			ret = make_error(protocol::errc::data_not_held);
		} else {
			issued.ticket = data_ticket{sid, committed.value(), data_server, data_right::replicate, now + validity_};
			issued.ticket.sign(*server_key);
			ret = std::move(issued);
		}
	}
	return ret;
}

}
