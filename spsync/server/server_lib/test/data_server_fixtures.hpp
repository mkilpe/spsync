#pragma once

#include <spsync/transfer/data_downloader.hpp>
#include <spsync/transfer/data_uploader.hpp>
#include <spsync/transfer/net_data_channel.hpp>
#include <spsync/server/server_lib/data_server.hpp>
#include <spsync/server/server_lib/storage.hpp>
#include <spsync/server/server_lib/storage_server.hpp>
#include <spsync/server/server_lib/ticket_issuer.hpp>
#include <spsync/test/test_ports.hpp>
#include <spsync/test/test_record_data.hpp>

#include <securepath/crypto/private_data_access.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <algorithm>
#include <chrono>
#include <mutex>
#include <thread>
#include <spsync/util/move_only_function.hpp>

/// the servers of the record data tests and a client's part against them
namespace securepath::sync::test {

/// how an all-in-one server is set up
struct all_in_one_params {
	std::string root;
	/// the slot of its listener ports (test_ports.hpp): record, s2s and data
	int slot{};
	std::vector<peer_config> peers;
	/// the data servers of the storages (RD12); none = the record role issues no tickets
	std::vector<data_endpoint> data_servers;
	/// record servers besides itself whose tickets the data role takes
	std::vector<peer_config> trusted_record_servers;
};

/// an all-in-one server (RD12): record role and data role over one context and root
struct all_in_one {
	all_in_one(network::context& context, all_in_one_params params)
	: context(context)
	, root(params.root)
	, records(context, record_params(params))
	, data(context, data_params(params))
	{
		records.attach_data_role(data);
	}

	static storage_server_params record_params(all_in_one_params const& p) {
		storage_server_params ret;
		ret.storage_root = p.root;
		ret.storage_server_endpoint = loopback(server_ports(p.slot).client);
		ret.s2s_endpoint = loopback(server_ports(p.slot).s2s);
		ret.peers = p.peers;
		ret.data_servers = p.data_servers;
		return ret;
	}

	static data_server_params data_params(all_in_one_params const& p) {
		data_server_params ret;
		ret.enabled = true;
		ret.storage_root = p.root;
		ret.data_endpoint = loopback(server_ports(p.slot).data);
		ret.record_servers = p.trusted_record_servers;
		return ret;
	}

	void start() {
		data.start();
		records.start();
	}

	void close() {
		records.close();
		data.close();
	}

	/// the key of both roles
	crypto::private_key key() const {
		return crypto::my_private_key(context.private_data());
	}

	/// the data role as a client is told of it; the server must be running
	data_endpoint endpoint() const {
		return data_endpoint{"127.0.0.1", data.local_endpoint()->port(), key().id(), {}, {}};
	}

public:
	network::context& context;
	std::string root;
	storage_server records;
	data_server data;
};

/// tickets a record server signs for one client without looking at a chain: for the
/// data role alone
inline ticket_source signed_tickets(crypto::private_key signer, std::vector<data_endpoint> holders, protocol::storage_id sid
	, crypto::public_key_id client, std::chrono::seconds validity = std::chrono::seconds{600}) {
	return [signer, holders, sid, client, validity](data_descriptor const& d, data_right right
		, move_only_function<void(util::result<data_grant>)> cb) {
		data_ticket ticket{sid, d, client, right, clock_type::now() + validity};
		ticket.sign(signer);
		cb(util::result<data_grant>{data_grant{std::move(ticket), holders}});
	};
}

/// the record server's part of a client's transfer, as its connection handler does it
inline ticket_source tickets_of(storage_server& records, std::shared_ptr<storage> const& storage, network::context& record_context
	, std::vector<data_endpoint> const& servers, crypto::public_key_id const& member) {
	return [&records, storage, &record_context, servers, member](data_descriptor const& d, data_right right
		, move_only_function<void(util::result<data_grant>)> cb) {
		ticket_issuer issuer{servers, records.availability(), std::chrono::seconds{600}};
		auto issued = issuer.issue(storage->id(), storage->committed_data(d.manifest_digest), member
			, static_cast<std::uint32_t>(right), record_context.private_data().my_private_key(), clock_type::now());
		if(issued) {
			cb(util::result<data_grant>{data_grant{std::move(issued->ticket), std::move(issued->holders)}});
		} else {
			cb(util::result<data_grant>{issued.get_error()});
		}
	};
}

/// upload one data of the store with the given tickets: how it ended
inline std::optional<error> upload(record_data_store& store, network::context& client_context, ticket_source source, data_id const& id) {
	net_data_channel channel{client_context, std::move(source)};
	transfer_log log;
	data_uploader uploader{store, channel, data_upload_config{}, log.done()};
	REQUIRE(uploader.enqueue(id));
	WAIT_REQUIRE(log.count == 1, std::chrono::seconds{30});
	std::unique_lock lock{log.mutex};
	return log.finished.front().second;
}

/// download one opened data of the store with the given tickets: how it ended
inline std::optional<error> download(record_data_store& store, network::context& client_context, ticket_source source, data_id const& id) {
	net_data_channel channel{client_context, std::move(source)};
	transfer_log log;
	data_downloader downloader{store, channel, data_download_config{}, log.done()};
	REQUIRE(downloader.enqueue(id));
	WAIT_REQUIRE(log.count == 1, std::chrono::seconds{30});
	std::unique_lock lock{log.mutex};
	return log.finished.front().second;
}

/// a whole chunk into an opened upload, the way the wire brings it: as one piece. A
/// chunk held already stays as it is (the store refuses to stage it again): true when the
/// data is complete
inline util::result<bool> store_whole_chunk(server_data_store& store, data_id const& id, std::uint64_t chunk_no
	, octet_span chunk, time_point now) {
	auto const row = store.find(id);
	if(row && row->have.test(chunk_no)) {
		return row->state == record_data_state::in_sync;
	}
	auto begun = store.begin_chunk(id, chunk_no, now);
	if(!begun) {
		return begun.get_error();
	}
	if(!begun.value().append(0, chunk)) {
		return make_error(protocol::errc::invalid_data_chunk);
	}
	return store.finish_chunk(id, begun.value(), now);
}

/// the data server holds the whole data
inline bool holds(data_server& server, protocol::storage_id const& sid, data_id const& id) {
	auto const row = server.find(sid, id);
	return row && row->state == record_data_state::in_sync;
}

/// data servers the record server knows to hold the whole data
inline std::size_t complete_holders(storage_server const& records, protocol::storage_id const& sid, data_id const& id) {
	auto const holdings = records.availability().holdings(sid, id);
	return static_cast<std::size_t>(std::ranges::count_if(holdings, &data_holding::complete));
}

}
