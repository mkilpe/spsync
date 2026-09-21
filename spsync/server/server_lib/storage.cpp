#include "storage.hpp"

#include <spsync/core/data/data_state_table.hpp>
#include <spsync/core/database_util.hpp>

#include <utility>
#include "connection.hpp"

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <spsync/protocol/error.hpp>

#include <securepath/crypto/private_data_access.hpp>

#include <ctime>
#include <filesystem>

namespace securepath::sync {
namespace {

void create_or_upgrade_config_table(database::connection& db) {
	if(!db.has_table("storage_config")) {
		db.prepare("CREATE TABLE storage_config("
			"key INTEGER PRIMARY KEY CHECK(key = 1),"
			"sync_mode INTEGER,"
			"auth_mode INTEGER,"
			"replication INTEGER,"
			"max_record_size INTEGER,"
			"chunk_size INTEGER,"
			"created_at INTEGER);").execute();
	} else if(!has_column(db, "storage_config", "max_record_size")) {
		// a storage from before RDS 8: it gets the compiled defaults, the same on every replica
		db.prepare("ALTER TABLE storage_config ADD COLUMN max_record_size INTEGER;").execute();
		db.prepare("ALTER TABLE storage_config ADD COLUMN chunk_size INTEGER;").execute();
	}
}

std::optional<storage_modes> load_persisted_modes(database::connection& db) {
	std::optional<storage_modes> ret;
	auto q = db.prepare("SELECT sync_mode, auth_mode, replication, max_record_size, chunk_size FROM storage_config WHERE key = 1;");
	auto res = q.execute();
	if(res) {
		ret = storage_modes{
			sync_mode(res.value<std::int64_t>(0).value_or(0)),
			auth_mode(res.value<std::int64_t>(1).value_or(0)),
			replication_mode(res.value<std::int64_t>(2).value_or(0)),
			storage_limits{
				static_cast<std::uint32_t>(res.value<std::int64_t>(3).value_or(default_max_record_size)),
				static_cast<std::uint32_t>(res.value<std::int64_t>(4).value_or(default_chunk_size))}};
	}
	return ret;
}

void persist_modes(database::connection& db, storage_modes const& m, std::string const& log_id) {
	auto ins = db.prepare("INSERT INTO storage_config(key, sync_mode, auth_mode, replication, max_record_size, chunk_size, created_at)"
		" VALUES(1, :m, :a, :r, :mr, :cs, :c);");
	ins.bind(":m", std::to_underlying(m.mode));
	ins.bind(":a", std::to_underlying(m.auth));
	ins.bind(":r", std::to_underlying(m.replication));
	ins.bind(":mr", static_cast<std::int64_t>(m.limits.max_record_size));
	ins.bind(":cs", static_cast<std::int64_t>(m.limits.chunk_size));
	ins.bind(":c", static_cast<std::int64_t>(std::time(nullptr)));
	ins.execute();
	LOG_INFO("storage modes persisted [mode={}, auth={}, replication={}, max_record_size={}, chunk_size={}] (rsid={})",
		int(m.mode), int(m.auth), int(m.replication), m.limits.max_record_size, m.limits.chunk_size, log_id);
}

/**
 * The persisted modes, or the requested ones persisted on first creation with unstated
 * limits filled from the server defaults (RDS 8). A stated mode that does not match the
 * persisted one is a storage_mode_mismatch; limits outside their ranges are
 * invalid_storage_modes.
 */
/// a rejection that no later state can lift: the record itself is not acceptable here
bool permanent_rejection(error const& err) {
	return err.code() == make_error_code(protocol::errc::invalid_record)
		|| err.code() == make_error_code(protocol::errc::record_too_big)
		|| err.code() == make_error_code(protocol::errc::conflicting_record);
}

storage_modes load_or_create_modes(database::connection& db, std::optional<storage_modes> const& requested,
	storage_limits const& defaults, std::string const& log_id)
{
	create_or_upgrade_config_table(db);
	if(auto persisted = load_persisted_modes(db)) {
		if(requested && !modes_match(*requested, *persisted)) {
			LOG_WARN("storage exists with different modes (rsid={})", log_id);
			throw make_error(protocol::errc::storage_mode_mismatch, "storage exists with different modes");
		}
		return *persisted;
	}
	if(!requested) {
		// a database without modes: a creation that did not get to persist them
		LOG_INFO("storage database without persisted modes, not a storage (rsid={})", log_id);
		throw make_error(protocol::errc::no_such_storage, "no such storage");
	}
	storage_modes m = *requested;
	if(m.limits.max_record_size == 0) {
		m.limits.max_record_size = defaults.max_record_size;
	}
	if(m.limits.chunk_size == 0) {
		m.limits.chunk_size = defaults.chunk_size;
	}
	if(!valid_storage_limits(m.limits)) {
		LOG_WARN("invalid default storage limits (rsid={})", log_id);
		throw make_error(protocol::errc::invalid_storage_modes, "invalid storage limits");
	}
	persist_modes(db, m, log_id);
	return m;
}

}

storage::storage(protocol::storage_id id, storage_config config, std::optional<storage_modes> create_modes,
	crypto::public_key_access* keys, crypto::private_data_access* private_data)
: config_(std::move(config))
, id_(std::move(id))
, keys_(keys)
, private_data_(private_data)
{
	std::string path = config_.storage_root_path() + "/" + to_hex(id_);
	std::string db = path + "/storage.db";
	LOG_INFO("Constructing storage using path: {}", db);

	// a storage comes into being only through an explicit creation with valid modes; a
	// plain load of an unknown id must not leave a default mode storage behind, and a
	// refused creation must not leave a database behind either (checked before opening)
	if(create_modes && !valid_storage_modes(*create_modes)) {
		LOG_WARN("invalid storage modes: a replicated storage requires signed records, limits must be in range (rsid={})", to_hex(id_));
		throw make_error(protocol::errc::invalid_storage_modes, "invalid storage modes");
	}
	if(!create_modes && !std::filesystem::exists(db)) {
		LOG_INFO("no such storage (rsid={})", to_hex(id_));
		throw make_error(protocol::errc::no_such_storage, "no such storage");
	}

	//make sure the path exists, this does nothing if it already does
	std::filesystem::create_directories(path);

	auto db_conn = database::sqlite::create_sqlite_connection(db);
	modes_ = load_or_create_modes(*db_conn, create_modes, config_.default_limits(), to_hex(id_));
	chain_sync_config sync_config{modes_.mode, modes_.auth, to_hex(id_)};
	sync_config.replication = modes_.replication;
	sync_config.max_record_size = modes_.limits.max_record_size;

	sync_ = std::make_unique<chain_sync>(db_conn, sync_config, keys);
	heads_ = std::make_unique<storage_heads>(db_conn);
	db_ = db_conn;
	if(!db_->has_table("replica_state")) {
		db_->prepare("CREATE TABLE replica_state("
			"key INTEGER PRIMARY KEY CHECK(key = 1),"
			"bootstrapping INTEGER);").execute();
	}
	auto q = db_->prepare("SELECT bootstrapping FROM replica_state WHERE key = 1;");
	if(auto res = q.execute()) {
		bootstrapping_ = res.value<std::int64_t>(0).value_or(0) != 0;
	}
	if(private_data_) {
		if(auto key = private_data_->my_private_key()) {
			own_id_ = key->id();
		}
	}
}

std::vector<origin_head> storage::heads() const {
	std::unique_lock l{mutex_};
	std::vector<origin_head> ret;
	if(own_id_.is_valid()) {
		// the own head is derived live from the log so it cannot go stale: the last record
		// we assigned ourselves (plan 5.2), term 0 until phase 6
		auto own = sync_->log().origin_head(own_id_);
		if(own.is_valid()) {
			ret.push_back(origin_head{own_id_, 0, own});
		}
	}
	for(auto& head : heads_->all()) {
		if(head.origin != own_id_) {
			ret.push_back(std::move(head));
		}
	}
	return ret;
}

sequence_number storage::current_sequence_number() const {
	std::unique_lock l{mutex_};
	return sync_->current_sequence_number();
}

std::deque<chain_block> storage::get_records(sequence_number start, sequence_number end) const {
	std::unique_lock l{mutex_};
	return sync_->get_records(start, end);
}

std::deque<block_envelope> storage::get_envelopes(sequence_number start, sequence_number end) const {
	std::unique_lock l{mutex_};
	return sync_->get_envelopes(start, end);
}

std::deque<block_envelope> storage::get_envelopes_by_origin(crypto::public_key_id const& origin,
	sequence_number from, sequence_number to) const {
	std::unique_lock l{mutex_};
	return sync_->get_envelopes_by_origin(origin, from, to);
}

sequence_number storage::known_origin_seq(crypto::public_key_id const& origin) const {
	std::unique_lock l{mutex_};
	if(origin == own_id_) {
		return sync_->log().origin_head(own_id_).sequence;
	}
	sequence_number ret;
	if(auto head = heads_->find(origin)) {
		ret = head->block.sequence;
	}
	return ret;
}

std::optional<block_envelope> storage::make_envelope(chain_block const& block) const {
	std::optional<block_envelope> env;
	if(private_data_) {
		auto key = private_data_->my_private_key();
		if(key) {
			env = block_envelope{block, key->id()};
			env->sign(id_, *key);
		}
	}
	return env;
}

storage::commit_outcome storage::commit_block(chain_block const& cb) {
	std::unique_lock l{mutex_};
	commit_outcome outcome{sync_->commit_block(cb)};
	if(outcome.block) {
		outcome.envelope = make_envelope(outcome.block.value());
		if(outcome.envelope) {
			// keep the signed assignment in the log so replication can serve it later
			sync_->log().store_assignment(outcome.block.value().tag(), *outcome.envelope);
			// weak replication: the origin pushes its own commits to the peers (plan 4.2)
			if(modes_.replication == replication_mode::weak && peer_push_) {
				peer_push_(id_, modes_, *outcome.envelope);
			}
		}
		notify_listeners(outcome.block.value(), outcome.envelope);
	}
	return outcome;
}

error storage::apply_foreign(block_envelope const& env) {
	std::unique_lock l{mutex_};
	if(modes_.replication != replication_mode::weak) {
		return make_error(protocol::errc::invalid_state, "storage does not replicate in weak mode");
	}
	if(!keys_) {
		return make_error(securepath::errc::invalid_state, "no key access to verify the origin");
	}
	if(auto err = env.verify(id_, *keys_)) {
		LOG_WARN("foreign envelope does not verify [origin={}] (rsid={})", env.origin(), to_hex(id_));
		return err;
	}
	if(env.origin() == own_id_) {
		// our own record came back around
		return {};
	}
	auto const& block = env.block();
	// the origin head is kept fresh for records we already hold, but never advanced past
	// a record that did not apply: anti-entropy pulls from the head, so the record would
	// be skipped for good (found by the 5.2 bootstrap: a signer key learned later)
	origin_head const head{env.origin(), env.term(), block.id()};
	if(sync_->records().find_tag(block.tag())) {
		heads_->advance(head);
		return {};
	}
	auto res = sync_->commit_foreign(block);
	if(!res) {
		if(check_result_error(res, protocol::errc::record_already_committed)) {
			// same operation under another tag was adopted already (op id dedup)
			heads_->advance(head);
			return {};
		}
		if(permanent_rejection(res.get_error())) {
			// the origin accepted what our rules refuse (a validity disagreement or a
			// misbehaving origin): retrying can never change the verdict, so the record
			// is skipped and the origin head moves past it - anti-entropy goes on and the
			// storage does not stay "syncing" for good. Logged once, here.
			LOG_WARN("foreign record rejected for good, skipped [origin={}, origin seq={}, tag={}, err={}] (rsid={})"
				, env.origin(), block.sequence(), to_hex(block.tag()), res.get_error(), to_hex(id_));
			heads_->advance(head);
			return {};
		}
		LOG_WARN("foreign record was not accepted [origin={}, err={}] (rsid={})"
			, env.origin(), res.get_error(), to_hex(id_));
		return res.get_error();
	}
	heads_->advance(head);
	// the record now lives under our own sequence; the log keeps the ORIGIN's signed
	// assignment - it is the durable (origin id, origin seq) needed by anti-entropy
	sync_->log().store_assignment(block.tag(), env);
	notify_listeners(res.value(), make_envelope(res.value()));
	return {};
}

bool storage::bootstrapping() const {
	std::unique_lock l{mutex_};
	return bootstrapping_;
}

void storage::set_bootstrapping(bool on) {
	std::unique_lock l{mutex_};
	if(bootstrapping_ != on) {
		LOG_INFO("replica {} (rsid={})", on ? "bootstrapping" : "caught up with its peers", to_hex(id_));
		bootstrapping_ = on;
		auto q = db_->prepare("INSERT OR REPLACE INTO replica_state(key, bootstrapping) VALUES(1, :b);");
		q.bind(":b", static_cast<std::int64_t>(on ? 1 : 0));
		q.execute();
	}
}

void storage::set_peer_push(peer_push_hook hook) {
	std::unique_lock l{mutex_};
	peer_push_ = std::move(hook);
}

std::optional<data_descriptor> storage::committed_data(data_id const& id) const {
	std::unique_lock l{mutex_};
	std::optional<data_descriptor> ret;
	auto const row = data_state_table{db_}.find(id);
	if(row && sync_->records().data_reference_count(row->local_id) != 0) {
		ret = row->descriptor;
	}
	return ret;
}

void storage::add_listener(std::shared_ptr<connection> const& p) {
	std::unique_lock l{mutex_};
	listeners_[&*p] = p;
}

void storage::for_each_listener(std::function<void(connection&)> const& f) {
	for(auto it = listeners_.begin(); it != listeners_.end(); ) {
		auto p = it->second.lock();
		if(p) {
			f(*p);
			++it;
		} else {
			it = listeners_.erase(it);
		}
	}
}

void storage::notify_listeners(chain_block const& c, std::optional<block_envelope> const& env) {
	for_each_listener([&](connection& conn) { conn.notify(id_, c, env); });
}

void storage::notify_data(data_id const& id, bool complete) {
	std::unique_lock l{mutex_};
	for_each_listener([&](connection& conn) { conn.notify_data(id_, id, complete); });
}

}

