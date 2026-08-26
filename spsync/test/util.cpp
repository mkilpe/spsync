#include "util.hpp"

namespace securepath::sync::test {

database::connection_ptr create_test_database(std::string const& db_name, bool remove) {
	if(remove) {
		std::remove(db_name.c_str());
	}
	return database::sqlite::create_sqlite_connection(db_name);
}

bool check_record_matches(sequence_number seq, int client_n, record_handle sh, record_handle ch) {
	bool ret = false;
	if(sh) {
		if(ch) {
			if(sh->tag() == ch->tag()) {
				ret = sh->parent_block_hash() == ch->parent_block_hash();
				if(!ret) {
					LOG_WARN("parent block hash for sequence {} does not match: server({}) - client {}({})", seq, to_hex(sh->parent_block_hash()), client_n, to_hex(ch->parent_block_hash()));
				}
			} else {
				LOG_WARN("tag for sequence {} does not match: server({}) - client {}({})", seq, to_hex(sh->tag()), client_n, to_hex(ch->tag()));
			}
		} else {
			LOG_WARN("client {} sequence number {} missing", client_n, seq);
		}
	} else {
		LOG_WARN("server sequence number {} missing", seq);
	}
	return ret;
}

bool check_commit_records_equal(sequence_number last_seq, record_storage const& c1, record_storage const& c2) {
	bool ret = true;
	if(c1.last_block().sequence != c2.last_block().sequence || c1.last_block().sequence != last_seq) {
		ret = false;
		LOG_WARN("last sequence number mismatch (seq={}): {} != {}", last_seq, c1.last_block().sequence, c2.last_block().sequence);
	} else {
		for(sequence_number seq{1}; ret && seq != last_seq+1; ++seq) {
			ret = check_record_matches(seq, 0, c1.find(seq), c2.find(seq));
		}
	}
	return ret;
}

}
