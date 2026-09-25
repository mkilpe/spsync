// SPDX-License-Identifier: MIT

#include "contact_list.hpp"

#include <securepath/common/key_value_database.hpp>

namespace securepath::sync::client {

contact_list::contact_list(database::connection_ptr db)
: db_(db)
{
	if(!db->has_table("contacts")) {
		LOG_TRACE("creating contacts table to db");
		std::string prepare_str =
			"CREATE TABLE contacts("
				"key INTEGER PRIMARY KEY,"
				"key_id TEXT UNIQUE);";
		db->prepare(prepare_str).execute();
	}
}

std::deque<std::unique_ptr<contact>> contact_list::enumerate() const {
	std::deque<std::unique_ptr<contact>> ret;
	auto q = db_->prepare("SELECT key, key_id FROM contacts;");

	auto res = q.execute();
	for(; res; res.next()) {
		auto key = res.value<std::int64_t>(0);
		if(key) {
			user_id uid{crypto::public_key_id{*res.value<octet_vector>(1)}};
			auto p = std::make_unique<contact>(uid);
			p->add_backend(std::make_shared<key_value_database>(db_, "contacts_metadata", static_cast<std::uint64_t>(*key)));
			ret.push_back(std::move(p));
		}
	}
	return ret;
}

std::unique_ptr<contact> contact_list::find(user_id const& uid) const {
	std::unique_ptr<contact> ret;
	auto q = db_->prepare("SELECT key FROM contacts WHERE key_id = :id");
	q.bind(":id", uid.public_key_id().data());

	auto res = q.execute();
	if(res) {
		auto key = res.value<std::int64_t>(0);
		if(key) {
			ret = std::make_unique<contact>(uid);
			ret->add_backend(std::make_shared<key_value_database>(db_, "contacts_metadata", static_cast<std::uint64_t>(*key)));
		}
	}
	return ret;
}

std::unique_ptr<contact> contact_list::add(user_id const& uid) {
	if(!uid.is_valid()) {
		throw make_error(securepath::errc::invalid_data, "invalid user id");
	}
	auto q = db_->prepare("INSERT OR REPLACE INTO contacts(key_id) VALUES(:id);");
	q.bind(":id", uid.public_key_id().data());
	q.execute();
	return find(uid);
}

void contact_list::remove(user_id const& uid) {
	auto q = db_->prepare("DELETE FROM contacts WHERE key_id = :id");
	q.bind(":id", uid.public_key_id().data());
	q.execute();
}

}
