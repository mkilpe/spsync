#include "config.hpp"

#include <securepath/log/log.hpp>
#include <securepath/util/string_util.hpp>
#include <securepath/util/error.hpp>

namespace securepath::sync::util {

config::config(database::connection_ptr db, std::string_view tablename)
: db_(db)
, tablename_(tablename)
{
	if(!db_->has_table(tablename_)) {
		std::string prepare_str =
			"CREATE TABLE " + tablename_ + "("
				"key STRING PRIMARY KEY, "
				"value STRING);";
		db_->prepare(prepare_str).execute();
	}
	load();
}

void config::set_database(database::connection_ptr db, std::string_view tablename) {
	std::unique_lock l{mutex_};
	db_ = db;
	tablename_ = tablename;

	if(!db_->has_table(tablename_)) {
		std::string prepare_str =
			"CREATE TABLE " + tablename_ + "("
				"key STRING PRIMARY KEY, "
				"value STRING);";
		db_->prepare(prepare_str).execute();
	}

	update_db("", root_);
	root_ = {};
	load();
}

void config::load() {
	auto q = db_->prepare("SELECT key, value FROM " + tablename_);
	auto res = q.execute();
	for(; res; res.next()) {
		std::string value_str = res.value<std::string>(1).value();
		std::error_code ec;
		auto value = json::parse(value_str, ec);
		if(ec) {
			LOG_WARN("ignoring invalid value in config: '{}'", value_str);
		} else {
			set_impl(res.value<std::string>(0).value(), value, true);
		}
	}
}

void config::update_db(std::string_view key, json::value const& v) {
	// recursively write objects to database as single non-object entities
	if(v.is_object()) {
		for(auto value : v.as_object()) {
			std::string next_key{key};
			if(!next_key.empty()) {
				next_key += ".";
			}
			next_key += value.key();
			update_db(next_key, value.value());
		}
	} else {
		auto q = db_->prepare("INSERT OR REPLACE INTO " + tablename_ + " VALUES(:key,:value);");
		q.bind(":key", key);
		q.bind(":value", json::serialize(v));
		q.execute();

		events_.emit<events::on_config_changed>(key);
	}
}

void config::remove_db(std::string_view key, json::value const& v) {
	if(v.is_object()) {
		for(auto value : v.as_object()) {
			std::string next_key{key};
			if(!next_key.empty()) {
				next_key += ".";
			}
			next_key += value.key();
			remove_db(next_key, value.value());
		}
	} else {
		auto q = db_->prepare("DELETE FROM " + tablename_ + " WHERE key = :key");
		q.bind(":key", key);
		q.execute();

		events_.emit<events::on_config_changed>(key);
	}
}

void config::set_impl(std::string_view key, json::value const& v, bool overwrite) {
	json::object* cur = &root_;
	auto key_parts = split_view(key, ".");
	for(std::size_t i = 0; i != key_parts.size(); ++i) {
		if(i != key_parts.size()-1) {
			auto it = cur->find(key_parts[i]);
			if(it != cur->end()) {
				if(it->value().is_object()) {
					cur = &it->value().as_object();
				} else {
					if(!overwrite) {
						throw make_error(errc::constraint_violation, "trying to overwrite config branch");
					}
					cur = &cur->insert_or_assign(key_parts[i], json::object{}).first->value().as_object();
				}
			} else {
				cur = &cur->insert_or_assign(key_parts[i], json::object{}).first->value().as_object();
			}
		} else {
			// last part
			cur->insert_or_assign(key_parts[i], v);
		}
	}
}

void config::set(std::string_view option, json::value const& v, bool only_leaf) {
	LOG_TRACE("config set [{} = {}]", option, json::serialize(v));
	std::unique_lock l{mutex_};
	set_impl(option, v, !only_leaf);
	if(db_) {
		update_db(option, v);
	}
}

std::optional<json::value> config::find(std::string_view option) const {
	std::unique_lock l{mutex_};
	std::optional<json::value> ret;
	json::object const* cur = &root_;
	auto key_parts = split_view(option, ".");
	if(!key_parts.empty()) {
		for(std::size_t i = 0; i != key_parts.size()-1; ++i) {
			auto it = cur->find(key_parts[i]);
			if(it == cur->end() || !it->value().is_object()) {
				return std::nullopt;
			}
			cur = &it->value().as_object();
		}
		auto it = cur->find(key_parts.back());
		if(it != cur->end()) {
			ret = it->value();
		}
	}
	return ret;
}

json::value config::get(std::string_view option) const {
	auto v = find(option);
	if(!v) {
		throw make_error(errc::no_such_data, std::string(option));
	}
	return *v;
}

json::value config::get_default(std::string_view option, json::value const& def) const {
	auto v = find(option);
	return v.value_or(def);
}

void config::remove(std::string_view option) {
	std::unique_lock l{mutex_};
	json::object* cur = &root_;
	auto key_parts = split_view(option, ".");
	if(!key_parts.empty()) {
		for(std::size_t i = 0; i != key_parts.size()-1; ++i) {
			auto it = cur->find(key_parts[i]);
			if(it == cur->end() || !it->value().is_object()) {
				return;
			}
			cur = &it->value().as_object();
		}
		auto it = cur->find(key_parts.back());
		if(it != cur->end()) {
			json::value v = it->value();
			cur->erase(it);
			if(db_) {
				remove_db(option, v);
			}
		}
	}
}

event_system::broadcast_event_handler& config::change_notification() {
	return events_;
}

}
