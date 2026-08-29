#pragma once

#include <spsync/core/records/chain_block.hpp>
#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <securepath/crypto/private_key.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::sync::test {


struct test_block_creator {

	record_base next_record_base() {
		auto op = force_op_id.value_or(securepath::test::random_octet_vector(16));
		force_op_id.reset();
		return record_base{chain_block_id{last_server_seq++, last_chain_hash}, octet_vector{}, sequence_number{1}, std::move(op)};
	}

	template<typename Record>
	chain_block next_block(auth_record<Record> test_record) {
		if(signer) {
			test_record.auth.sign(*signer, serialisation::asn_der_serialise_choice<record_types>(test_record.record));
		}
		chain_block block{test_record};
		block.set_sequence_and_parent_hash(last_server_seq, last_chain_hash);
		last_chain_hash = block.hash();
		last_tag = test_record.auth.tag();
		return block;
	}

	/// Create empty user change record for testing
	chain_block test_user_change() {
		record_tag tag = securepath::test::random_octet_vector(16);
		auth_record<user_change_record> test_record{
			user_change_record{next_record_base(), plain_user_change_data{},
				encrypted_record_header<user_change_header>{}}, util::content_auth{tag}};
		return next_block(test_record);
	}

	/// Create data change record with one object id for testing
	chain_block test_data_change(record_tag tag = securepath::test::random_octet_vector(16)) {
		return test_multi_data_change(1, tag);
	}

	/// Create data change record with multiple object ids for testing
	chain_block test_multi_data_change(std::size_t amount, record_tag tag = securepath::test::random_octet_vector(16)) {
		auth_record<data_change_record> test_record{data_change_record{next_record_base()}, util::content_auth{tag}};
		for(std::size_t i = 0; i != amount; ++i) {
			test_record.record.add(single_change{plain_single_change_data{util::create_object_id()}, {}});
		}
		return next_block(test_record);
	}

	/// Create data change record that has same object ids as the given record and those set as the previous change of the object id
	chain_block test_followup_data_change(chain_block const& previous) {
		data_change_record rec = previous.deserialise_to<data_change_record>();
		record_tag tag = securepath::test::random_octet_vector(16);
		auth_record<data_change_record> test_record{data_change_record{next_record_base()}, util::content_auth{tag}};
		for(auto&& d : rec) {
			test_record.record.add(single_change{plain_single_change_data{d.data.id, previous.tag()}});
		}
		return next_block(test_record);
	}
	/*
	chain_block test_segment() {

	}
	*/
	/// when set, the next record base uses this operation id (single shot)
	std::optional<octet_vector> force_op_id;

	/// when set, created records are signed with this key
	std::optional<crypto::private_key> signer;

	sequence_number last_server_seq{};
	record_tag last_tag{};
	octet_vector last_chain_hash{};
};

}

