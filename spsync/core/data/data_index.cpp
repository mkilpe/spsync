// SPDX-License-Identifier: MIT

#include "data_index.hpp"

#include <spsync/core/record_interface.hpp>

#include <utility>

namespace securepath::sync {

data_index::data_index(database::connection_ptr db)
: db_(std::move(db))
{}

std::uint64_t data_index::reference(data_descriptor const& descriptor) {
	data_state_table table{db_, data_state_table::existing_schema{}};
	auto const local_id = table.ensure(descriptor);
	auto const row = table.find(local_id);
	if(row && row->state == record_data_state::pruned) {
		table.set_state(local_id, record_data_state::deferred);
	}
	return local_id;
}

std::uint64_t data_index::reference_count(std::uint64_t data_ref) const {
	auto q = db_->prepare("SELECT count(*) FROM record_objects WHERE data_ref = :d;");
	q.bind(":d", static_cast<std::int64_t>(data_ref));
	// a count is a plain integer (sequences are stored with the unsigned offset)
	return static_cast<std::uint64_t>(q.execute().value<std::int64_t>(0).value_or(0));
}

std::vector<data_id> data_index::confirmed_in_state(record_data_state state) const {
	auto q = db_->prepare(
		"SELECT record_data.data_id, min(record.seq) AS first_seq FROM record_objects"
		" JOIN record ON record.tag = record_objects.tag"
		" JOIN record_data ON record_data.key = record_objects.data_ref"
		" WHERE record_data.state = :ds AND (record.state = :s1 OR record.state = :s2)"
		" GROUP BY record_data.key ORDER BY first_seq ASC;");
	q.bind(":ds", static_cast<std::int64_t>(std::to_underlying(state)));
	q.bind(":s1", std::to_underlying(record_state::in_sync));
	q.bind(":s2", std::to_underlying(record_state::acked));

	std::vector<data_id> ret;
	for(auto res = q.execute(); res; res.next()) {
		auto id = res.value<octet_vector>(0);
		if(id) {
			ret.push_back(std::move(*id));
		}
	}
	return ret;
}

std::vector<data_id> data_index::unreferenced() const {
	std::vector<data_id> ret;
	auto q = db_->prepare(
		"SELECT data_id FROM record_data"
		" WHERE key NOT IN (SELECT data_ref FROM record_objects WHERE data_ref IS NOT NULL) ORDER BY key;");
	for(auto res = q.execute(); res; res.next()) {
		ret.push_back(res.value<octet_vector>(0).value_or(octet_vector{}));
	}
	return ret;
}

std::vector<data_id> data_index::remove_unreferenced() {
	data_state_table table{db_, data_state_table::existing_schema{}};
	auto tact = table.transaction();
	auto removed = unreferenced();
	for(auto const& id : removed) {
		if(auto const row = table.find(id)) {
			table.remove(row->local_id);
		}
	}
	return removed;
}

std::vector<data_state_row> data_index::only_referenced_by(std::map<std::uint64_t, std::uint64_t> const& references) const {
	std::vector<data_state_row> ret;
	data_state_table table{db_, data_state_table::existing_schema{}};
	for(auto const& [data_ref, count] : references) {
		auto row = table.find(data_ref);
		if(row && row->state != record_data_state::pruned && reference_count(data_ref) == count) {
			ret.push_back(std::move(*row));
		}
	}
	return ret;
}

std::vector<data_id> data_index::prune(std::vector<data_state_row> const& rows) {
	std::vector<data_id> pruned;
	data_state_table table{db_, data_state_table::existing_schema{}};
	auto tact = table.transaction();
	for(auto const& row : rows) {
		table.set_state(row.local_id, record_data_state::pruned);
		pruned.push_back(row.descriptor.manifest_digest);
	}
	return pruned;
}

}
