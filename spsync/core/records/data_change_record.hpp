#ifndef SPSYNC_CORE_DATA_CHANGE_RECORD_HEADER
#define SPSYNC_CORE_DATA_CHANGE_RECORD_HEADER

#include "data_change_header.hpp"
#include "encrypted_record_header.hpp"
#include "record_base.hpp"

#include <securepath/serialisation/deque.hpp>

#include <deque>

namespace securepath::sync {


struct plain_single_change_data {
	// id of the object this change affects
	object_id id;

	// tag of the previous record with same object id
	record_tag previous_oid_record_tag;

	// q: should we have change type (like remove) so that the server can remove unused data?

	serialisation::trailing_data trailing_data_;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & id & previous_oid_record_tag & trailing_data_;
	}
};

struct single_change  {
	single_change() = default;
	explicit single_change(plain_single_change_data data, encrypted_record_header<data_change_header> header = {})
	: data(std::move(data))
	, header(std::move(header))
	{}

	plain_single_change_data data;
	encrypted_record_header<data_change_header> header;
	serialisation::trailing_data trailing_data_;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & data & header & trailing_data_;
	}
};

class data_change_record : public record_base {
public:
	using const_iterator = std::deque<single_change>::const_iterator;

	data_change_record() = default;
	explicit data_change_record(record_base base, std::deque<single_change> changes = {})
	: record_base(std::move(base))
	, changes_(std::move(changes))
	{}

	bool is_single_change_record() const { return changes_.size() == 1; }

	const_iterator begin() const { return changes_.begin(); }
	const_iterator end() const { return changes_.end(); }

	void add(single_change change) {
		changes_.push_back(std::move(change));
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & static_cast<record_base&>(*this) & changes_ & trailing_data_;
	}
private:
	// this can be just a single change or aggregated multiple changes
	std::deque<single_change> changes_;
	serialisation::trailing_data trailing_data_;
};

}

#endif
