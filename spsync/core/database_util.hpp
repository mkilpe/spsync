#pragma once

#include <securepath/database/connection.hpp>

#include <string>

namespace securepath::sync {

/// true when the table has the column: how a database from before a column was added is told
inline bool has_column(database::connection& db, std::string const& table, std::string const& column) {
	bool found = false;
	auto q = db.prepare("PRAGMA table_info(" + table + ");");
	for(auto res = q.execute(); res && !found; res.next()) {
		found = res.value<std::string>(1).value_or("") == column;
	}
	return found;
}

}
