#include "channel_list.hpp"

namespace securepath::groupchat {

channel_list::channel_list(database::connection_ptr db)
: db_(db)
{
	if(!db_->has_table("channel_list")) {
		std::string prepare_str =
			"CREATE TABLE channel_list("
				"chat_id BLOB, "
				"server_host STRING, "
				"server_port INTEGER, "
				"PRIMARY KEY(chat_id, server_host, server_port));";
		db_->prepare(prepare_str).execute();
	}
}

void channel_list::add(chat_id const& cid, host_port const& server) {
	std::string s = "INSERT OR REPLACE INTO channel_list VALUES(:cid,:h,:p);";
	auto q = db_->prepare(s);
	q.bind(":cid", cid);
	q.bind(":h", server.host);
	q.bind(":p", static_cast<std::int64_t>(server.port));
	q.execute();
}

std::deque<channel_data> channel_list::enumerate(std::optional<host_port> server) const {
	std::deque<channel_data> ret;
	auto q = server
		? db_->prepare("SELECT chat_id, server_host, server_port FROM channel_list WHERE server_host = :h AND server_port = :p;")
		: db_->prepare("SELECT chat_id, server_host, server_port FROM channel_list;");
	if(server) {
		q.bind(":h", server->host);
		q.bind(":p", static_cast<std::int64_t>(server->port));
	}
	auto res = q.execute();
	for(; res; res.next()) {
		std::optional<chat_id> cid = res.value<chat_id>(0);
		std::optional<std::string> host = res.value<std::string>(1);
		std::optional<std::int64_t> port = res.value<std::int64_t>(2);
		if(cid && host && port) {
			ret.push_back(channel_data{host_port{*host, static_cast<std::uint16_t>(*port)}, *cid});
		}
	}
	return ret;
}

}
