#include "channel.hpp"
#include "groupchat.hpp"
#include "events.hpp"

#include <spsync/core/error.hpp>
#include <spsync/core/records/util.hpp>
#include <spsync/engine/record_verifier.hpp>
#include <spsync/client/record_util.hpp>

#include <spsync/core/data/source_record_data.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/serialisation/util.hpp>

#include <fstream>
#include <securepath/util/conversions.hpp>
#include <securepath/util/string_util.hpp>

namespace securepath::groupchat {

std::string const gc_name_tag = "gc.chat.name";
/// the block the chat's chain must start with (plan 5.5), from the invitation
std::string const gc_anchor_tag = "gc.chat.anchor";

std::string channel::db_path(chat_conn_context const& context, chat_id const& cid) {
	std::string path = context.path.empty() ? "" : context.path + "/";
	return path + to_hex(cid) + ".db";
}

std::string channel::data_path(chat_conn_context const& context, chat_id const& cid) {
	std::string path = context.path.empty() ? "" : context.path + "/";
	return path + to_hex(cid) + "-data";
}

namespace {

/// what a file is doing here from its record and its data (shared_files.txt SF-D7)
file_state state_of(sync::record_data_state data, bool own, bool pending_record) {
	if(pending_record) {
		return file_state::pending;
	}
	switch(data) {
	case sync::record_data_state::upload_pending:
	case sync::record_data_state::remote_not_complete:
		return file_state::sharing;
	case sync::record_data_state::download_pending:
		return file_state::fetching;
	case sync::record_data_state::in_sync:
		return own ? file_state::shared : file_state::fetched;
	case sync::record_data_state::removed:
		return file_state::removed;
	case sync::record_data_state::deferred:
	case sync::record_data_state::unknown:
		return file_state::on_server;
	case sync::record_data_state::invalid:
	case sync::record_data_state::pruned:
		return file_state::gone;
	}
	return file_state::gone;
}

}

static database::connection_ptr open_db(chat_conn_context& context, chat_id const& cid) {
	return database::sqlite::create_sqlite_connection(channel::db_path(context, cid));
}

channel::channel(chat_conn_context& context, chat_id const& cid)
: channel(context, cid, open_db(context, cid))
{
}

channel::channel(chat_conn_context& context, chat_id const& cid, database::connection_ptr db)
: client_sync(
	context.context,
	context.callback.event_loop(),
	db,
	sync::sync_engine_config{.mode=channel_storage_modes().mode, .auth_mode=channel_storage_modes().auth
		, .data_root=data_path(context, cid), .log_id=to_hex(cid)})
, ccontext_(context)
, chat_id_(cid)
, messages_(db)
, files_(db)
, db_(db)
, db_path_(db_path(context, cid))
, my_key_id_(my_private_key(context.context.private_data()).id())
{
	// make sure we are in sync with record storage and messages storage in case the application
	// was interrupted in between updating the messages storage
	sync_message_storage(messages_, crypto_context().records(), crypto_context().enc_keys());
	sync_file_storage(files_, crypto_context().records(), crypto_context().enc_keys());
	// a joined chat keeps anchoring on the invitation's first block (plan 5.5)
	if(auto anchor = find(gc_anchor_tag)) {
		set_trusted_anchor(serialisation::asn_der_deserialise<sync::chain_block_id>(*anchor));
	}
}

channel::~channel() {
	stop_handler();
}

std::string channel::name() const {
	return find<std::string>(gc_name_tag).value_or(to_hex(chat_id_));
}

void channel::set_data(std::string name, users members) {
	insert(gc_name_tag, name);

	std::unique_lock l{mutex_};
	initial_members_ = members;
}

void channel::set_join_data(sync::client::storage_info const& sinfo, std::string const& name) {
	insert(gc_name_tag, name);
	// the chain must start with the block the inviter named (plan 5.5): the server cannot
	// show this client another storage's history
	if(sinfo.chain_id.is_valid()) {
		insert(gc_anchor_tag, serialisation::asn_der_serialise(sinfo.chain_id));
		set_trusted_anchor(sinfo.chain_id);
	}

	// add encryption keys for the storage
	auto& keys = crypto_context().enc_keys();
	for(auto&& k : sinfo.enc_keys) {
		keys.insert(k);
	}
}

void channel::on_anchor_mismatch(sync::chain_block served) {
	LOG_WARN("the chat's history on the server does not start with the invited block [cid={}, seq={}]"
		, to_hex(chat_id_), served.sequence());
	ccontext_.callback.emit<events::on_join>(server_chat_id{ccontext_.sid, chat_id_}, sync::users{}
		, make_error(sync::errc::not_authentic, "the chat served is not the one invited to"));
}

void channel::on_data_change(sync::record_handle rec, std::deque<sync::single_data_change> changes) {
	LOG_TRACE("on_object_data_changed [count={}]", changes.size());

	std::unique_lock l{mutex_};
	database::transaction t{*db_};

	for(auto const& c : changes) {
		// check the previous oid for data record to ensure compatibility in the later versions when we do use it
		if(!c.data.previous_oid_record_tag.empty()) {
			LOG_WARN("data record with parent? (using old version of client?)");
		} else if(c.header.metadata().find<message_data>(groupchat_message_id)) {
			add_message(c);
		} else if(auto file = file_of(c)) {
			add_file(c, *file);
		} else {
			LOG_WARN("invalid record, no groupchat message or file found");
		}
	}
}

void channel::add_message(sync::single_data_change const& c) {
	auto opt = c.header.metadata().find<message_data>(groupchat_message_id);
	msg_data data{*opt, c.signer.value_or(crypto::public_key_id{}), c.internal_id, c.seq};
	auto change = messages_.insert(c.data.id, data, msg_state::in_sync);
	// notify higher level
	ccontext_.callback.emit<events::on_message>(server_chat_id{ccontext_.sid, chat_id_}, data, change);
}

void channel::add_file(sync::single_data_change const& c, stored_file const& file) {
	auto change = files_.insert(c.data.id, file, false);
	auto entry = entry_of(file_storage::row{c.data.id, file, change.new_index, false});
	ccontext_.callback.emit<events::on_file>(server_chat_id{ccontext_.sid, chat_id_}, entry, change);
}

bool channel::own(stored_file const& file) const {
	return file.sharer.public_key_id() == my_key_id_;
}

sync::record_data_handle channel::data_of(file_storage::row const& row) {
	sync::record_data_handle ret;
	if(auto record = crypto_context().records().find_internal(row.file.iid)) {
		ret = object_data(record);
	}
	return ret;
}

file_entry channel::entry_of(file_storage::row const& row) {
	auto const data = data_of(row);
	auto const state = state_of(data ? data->state() : sync::record_data_state::unknown, own(row.file), row.pending);
	return file_entry{row.id, row.file.data.name, row.file.data.mime, row.file.data.size, row.file.sharer
		, row.file.data.shared_time, row.index, state};
}

file_storage::row channel::stored_row(file_id const& id) const {
	auto row = files_.find(id);
	if(!row) {
		throw make_error(errc::no_such_data, "no such shared file");
	}
	return *row;
}

file_entry channel::share_file(std::filesystem::path const& path, std::string name, std::string mime) {
	file_data entry{std::move(name), std::move(mime), std::filesystem::file_size(path), clock_type::now()};
	sync::metadata header;
	header.insert(groupchat_file_id, entry);
	auto const id = sync::util::create_object_id();

	// the lock covers the send too, so the insert is done before the events come in
	std::unique_lock l{mutex_};
	auto handle = send_data_change(id, std::move(header), std::make_shared<sync::file_record_data>(path));
	// the data id is in the record: the descriptor the engine made of the source
	std::deque<sync::single_data_change> changes;
	auto const err = extract_single_data_changes(crypto_context().enc_keys(), handle, changes);
	auto stored = changes.empty() ? std::nullopt : file_of(changes.front());
	if(err || !stored) {
		throw make_error(errc::invalid_state, "the shared file's record cannot be read back");
	}
	stored->sharer = user_id{my_key_id_};
	auto const change = files_.insert(id, *stored, true);
	auto ret = entry_of(file_storage::row{id, *stored, change.new_index, true});
	ccontext_.callback.emit<events::on_file>(server_chat_id{ccontext_.sid, chat_id_}, ret, change);
	return ret;
}

std::deque<file_entry> channel::files(file_search s) {
	std::unique_lock l{mutex_};
	std::deque<file_entry> ret;
	for(auto const& row : files_.get(s)) {
		ret.push_back(entry_of(row));
	}
	return ret;
}

std::optional<file_entry> channel::file(file_id const& id) {
	std::unique_lock l{mutex_};
	std::optional<file_entry> ret;
	if(auto row = files_.find(id)) {
		ret = entry_of(*row);
	}
	return ret;
}

void channel::fetch_file(file_id const& id) {
	std::unique_lock l{mutex_};
	auto const row = stored_row(id);
	auto record = crypto_context().records().find_internal(row.file.iid);
	if(!record) {
		throw make_error(errc::no_such_data, "the shared file's record is gone");
	}
	fetch_object_data(record);
}

void channel::save_file(file_id const& id, std::filesystem::path const& path) {
	std::unique_lock l{mutex_};
	auto const data = data_of(stored_row(id));
	if(!data || data->state() != sync::record_data_state::in_sync) {
		throw make_error(errc::invalid_state, "the shared file is not fetched");
	}
	std::ofstream out(path, std::ios::binary | std::ios::trunc);
	if(!out) {
		throw make_error(errc::invalid_state, "cannot write the file");
	}
	octet_vector piece(1024 * 1024);
	std::uint64_t pos = 0;
	for(auto n = data->read(pos, piece.data(), piece.size()); n != 0; n = data->read(pos, piece.data(), piece.size())) {
		out.write(reinterpret_cast<char const*>(piece.data()), static_cast<std::streamsize>(n));
		pos += n;
	}
}

void channel::remove_file(file_id const& id) {
	std::unique_lock l{mutex_};
	if(auto data = data_of(stored_row(id))) {
		data->remove_data();
	}
}

void channel::on_data_state_changed(sync::data_id id, sync::record_data_state state) {
	std::unique_lock l{mutex_};
	if(auto fid = files_.find_by_data(id)) {
		auto const row = files_.find(*fid);
		bool const mine = row && own(row->file);
		ccontext_.callback.emit<events::on_file_state>(server_chat_id{ccontext_.sid, chat_id_}, *fid
			, state_of(state, mine, row && row->pending), error{});
	}
}

void channel::on_data_transfer_failed(sync::data_id id, error err) {
	std::unique_lock l{mutex_};
	if(auto fid = files_.find_by_data(id)) {
		auto const row = files_.find(*fid);
		auto const state = row ? entry_of(*row).state : file_state::gone;
		ccontext_.callback.emit<events::on_file_state>(server_chat_id{ccontext_.sid, chat_id_}, *fid, state, err);
	}
}

void channel::on_record_rejected(sync::record_handle rec, error err) {
	// the messages of a record the server refused for good stay pending forever otherwise
	std::deque<sync::single_data_change> changes;
	if(extract_single_data_changes(crypto_context().enc_keys(), rec, changes)) {
		LOG_WARN("rejected record could not be read [tag={}, err={}]", to_hex(rec->tag()), err);
	}
	std::unique_lock l{mutex_};
	for(auto const& c : changes) {
		if(messages_.remove_pending(c.data.id)) {
			LOG_WARN("message refused by the server [id={}, err={}]", c.data.id, err);
			ccontext_.callback.emit<events::on_message_failed>(server_chat_id{ccontext_.sid, chat_id_}, c.data.id, err);
		} else if(files_.remove_pending(c.data.id)) {
			LOG_WARN("shared file refused by the server [id={}, err={}]", c.data.id, err);
			ccontext_.callback.emit<events::on_file_state>(server_chat_id{ccontext_.sid, chat_id_}, c.data.id, file_state::gone, err);
		}
	}
}

void channel::on_user_change(sync::record_handle rec, sync::user_change usc) {
	if(rec->block_id().sequence == sync::sequence_number{1}) {
		if(usc.signer) {
			// check if we created the chat or not
			auto my_key = my_private_key(ccontext_.context.private_data());
			if(usc.signer == my_key.id()) {
				ccontext_.callback.emit<events::on_create>(server_chat_id{ccontext_.sid, chat_id_}, usc.members, error{});
			} else {
				ccontext_.callback.emit<events::on_join>(server_chat_id{ccontext_.sid, chat_id_}, usc.members, error{});
			}
		}
	}
	ccontext_.callback.emit<events::on_change_user>(server_chat_id{ccontext_.sid, chat_id_}, usc.members, error{});
}

void channel::create_initial_record() {
	auto own_key = ccontext_.context.private_data().my_private_key();
	assert(own_key);
	sync::metadata header;
	header.insert(groupchat_name_id, find<std::string>(gc_name_tag).value_or(to_hex(chat_id_)));

	std::unique_lock l{mutex_};
	sync::users initial = initial_members_;
	// always add ourself
	initial.add(sync::util::user_access{own_key->id(), sync::util::access_type::user_management_access});
	send_user_change(std::move(initial), std::move(header));
}

message channel::send_message(std::string_view msg) {
	message_data chat_msg{std::string{msg}, clock_type::now()};
	sync::metadata header;
	header.insert(groupchat_message_id, chat_msg);
	auto msg_id = sync::util::create_object_id();

	// lock mutex for send_data_change too to make sure the insert after it is always done before events come in
	std::unique_lock l{mutex_};
	auto handle = send_data_change(msg_id, std::move(header));

	msg_data data{chat_msg, my_key_id_, handle->internal_id()};
	auto change = messages_.insert(msg_id, data, msg_state::pending);

	return message{
		chat_msg.message,
		my_key_id_,
		msg_id,
		chat_msg.sender_time,
		change.new_index,
		change.state};
}

std::deque<message> channel::messages(message_search ms) const {
	std::unique_lock l{mutex_};
	return messages_.get(ms);
}

chat_id channel::id() const {
	return chat_id_;
}

sync::client::storage_info channel::storage_info() const {
	auto root = crypto_context().records().find_root();
	if(!root) {
		LOG_WARN("no root for storage?! [sid={}]", to_hex(chat_id_));
		throw make_error(errc::invalid_state, "could not find root record for storage");
	}

	return sync::client::storage_info{
		chat_id_,
		ccontext_.key_server,
		ccontext_.sync_server,
		root->block_id(),
		crypto_context().enc_keys().export_keys()
	};
}

}