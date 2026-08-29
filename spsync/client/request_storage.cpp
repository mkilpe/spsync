#include "request_storage.hpp"

#include <utility>

namespace securepath::sync::client {

request_storage::request_storage(database::connection_ptr db)
: db_(db)
{
	if(!db->has_table("requests")) {
		LOG_TRACE("creating requests table to db");
		std::string prepare_str =
			"CREATE TABLE requests("
				"key INTEGER PRIMARY KEY,"
				"state INTEGER,"
				"data BLOB,"
				"payload BLOB,"
				"time INTEGER);";
		db->prepare(prepare_str).execute();
	}
	if(!db->has_table("request_bans")) {
		LOG_TRACE("creating request_bans table to db");
		std::string prepare_str =
			"CREATE TABLE request_bans("
				"id BLOB PRIMARY KEY,"
				"time INTEGER);";
		db->prepare(prepare_str).execute();
	}
}

std::deque<db_request> request_storage::enumerate(std::optional<request_state> state) const {
	std::deque<db_request> ret;
	std::string qstr = "SELECT key, data, state, payload FROM requests";
	if(state) {
		qstr += " WHERE state = :state";
	}
	qstr += " ORDER BY time DESC";
	auto q = db_->prepare(qstr);
	if(state) {
		q.bind(":state", std::to_underlying(*state));
	}

	auto res = q.execute();
	for(; res; res.next()) {
		request r{{serialisation::asn_der_deserialise<request_data>(res.value<octet_vector>(1).value())}
				, res.value<std::int64_t>(0).value()
				, static_cast<request_state>(res.value<std::int64_t>(2).value())};

		ret.push_back(
			db_request{{std::move(r)}
				, serialisation::asn_der_deserialise<packet_transport::transport_payload>(res.value<octet_vector>(3).value())});
	}
	return ret;
}

std::optional<db_request> request_storage::find(request_id id) const {
	std::optional<db_request> ret;

	auto q = db_->prepare("SELECT data, state, payload FROM requests WHERE key = :id");
	q.bind(":id", id);

	auto res = q.execute();
	if(res) {
		request r{{serialisation::asn_der_deserialise<request_data>(res.value<octet_vector>(0).value())}
				, id
				, static_cast<request_state>(res.value<std::int64_t>(1).value())};
		ret = db_request{{std::move(r)}
				, serialisation::asn_der_deserialise<packet_transport::transport_payload>(res.value<octet_vector>(2).value())};
	}
	return ret;
}

void request_storage::change_state(request_id id, request_state state) {
	auto q = db_->prepare("UPDATE requests SET state = :state, time = :time WHERE key = :id;");
	q.bind(":id", id);
	q.bind(":state", std::to_underlying(state));
	q.bind(":time", clock_type::now());
	q.execute();
}

request_id request_storage::add(request_data const& d, packet_transport::transport_payload const& payload) {
	auto q = db_->prepare("INSERT INTO requests(state, data, payload, time) VALUES(:state, :data, :payload, :time);");
	q.bind(":state", std::to_underlying(request_state::waiting_for_verification));
	q.bind(":data", serialisation::asn_der_serialise(d));
	q.bind(":payload", serialisation::asn_der_serialise(payload));
	q.bind(":time", clock_type::now());
	q.execute();
	return q.last_inserted_row_id();
}

void request_storage::remove(request_id id) {
	auto q = db_->prepare("DELETE FROM requests WHERE key = :id");
	q.bind(":id", id);
	q.execute();
}

bool request_storage::is_sender_banned(crypto::public_key_id const& kid) const {
	bool ret = false;
	std::unique_lock l{mutex_};
	ret = banned_.count(kid);
	if(!ret) {
		auto q = db_->prepare("SELECT id FROM request_bans WHERE id = :id");
		q.bind(":id", kid.data());
		ret = static_cast<bool>(q.execute());
		if(ret) {
			banned_.insert(kid);
		}
	}
	return ret;
}

void request_storage::ban_sender(crypto::public_key_id const& kid) {
	auto q = db_->prepare("INSERT INTO request_bans(id, time) VALUES(:id, :time);");
	q.bind(":id", kid.data());
	q.bind(":time", clock_type::now());
	q.execute();
}


}
