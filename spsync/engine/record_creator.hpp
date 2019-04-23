#ifndef SPSYNC_ENGINE_RECORD_CREATOR_HEADER
#define SPSYNC_ENGINE_RECORD_CREATOR_HEADER



namespace securepath::sync {

//helper class to create records

// construction with encryption_key, previous record tag, creates random iv, initialise encryption/auth
// set client seq
// set other data
// set per record data, encrypt the record data
// in the end, give out full record with correct aes-gcm tag et al

}

#endif
