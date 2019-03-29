#ifndef SPSYNC_CORE_ENCRYPTED_RECORD_HEADER_HEADER
#define SPSYNC_CORE_ENCRYPTED_RECORD_HEADER_HEADER

namespace securepath::sync {

/**
 * Header for a record, keeps the HeaderType as encrypted
 */
template<typename HeaderType>
class encrypted_record_header {
public:
	using header_type = HeaderType;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & encrypted_header_ & trailing_data_;
	}
private:
	octet_vector encrypted_header_;
	serialisation::trailing_data trailing_data_;
};

}

#endif
