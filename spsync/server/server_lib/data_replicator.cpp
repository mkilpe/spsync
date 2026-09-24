#include "data_replicator.hpp"

#include <spsync/transfer/net_data_channel.hpp>

#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <map>
#include <mutex>

namespace securepath::sync {

class data_replicator::impl : public std::enable_shared_from_this<impl> {
public:
	impl(network::context& context, data_replicator_hooks hooks, data_download_config config, std::chrono::seconds timeout)
	: io_(context.io_context())
	, hooks_(std::move(hooks))
	, config_(config)
	, channel_(context, [this](data_descriptor const& d, data_right, std::move_only_function<void(util::result<data_grant>)> answer) {
			ask_ticket(d, std::move(answer));
		}, timeout)
	{}

	std::size_t replicate(protocol::storage_id const& sid, std::vector<data_descriptor> const& descriptors) {
		std::size_t queued = 0;
		try {
			auto const pulls = pulls_of(sid);
			for(auto const& descriptor : descriptors) {
				queued += replicate_one(sid, *pulls, descriptor) ? 1 : 0;
			}
		} catch(securepath::error const& err) {
			LOG_WARN("cannot hold copies for the storage: {} (sid={})", err, to_hex(sid));
		} catch(std::exception const& ex) {
			LOG_WARN("cannot hold copies for the storage: {} (sid={})", ex.what(), to_hex(sid));
		}
		return queued;
	}

	std::size_t pending() const {
		std::unique_lock lock{mutex_};
		return wanted_.size();
	}

	void close() {
		std::map<protocol::storage_id, std::shared_ptr<storage_pulls>> storages;
		{
			std::unique_lock lock{mutex_};
			storages.swap(storages_);
			wanted_.clear();
		}
		// the downloaders go without the lock: their reset may still call back
		storages.clear();
		channel_.close();
	}

private:
	/// the queue of one storage: its store and the downloader working on the store's chunks
	struct storage_pulls {
		std::shared_ptr<server_data_store> store;
		std::unique_ptr<data_downloader> downloader;
	};

	std::shared_ptr<storage_pulls> pulls_of(protocol::storage_id const& sid) {
		std::unique_lock lock{mutex_};
		auto it = storages_.find(sid);
		if(it == storages_.end()) {
			lock.unlock();
			auto pulls = std::make_shared<storage_pulls>();
			pulls->store = hooks_.store(sid);
			pulls->downloader = std::make_unique<data_downloader>(pulls->store->chunks(), channel_, config_
				, [weak = weak_from_this(), sid](data_id const& id, std::optional<error> err) {
					if(auto self = weak.lock()) {
						self->on_done(sid, id, err);
					}
				}, data_downloader::progress_callback{}, &io_);
			lock.lock();
			// two callers may have met here: the first one's stays
			it = storages_.try_emplace(sid, std::move(pulls)).first;
		}
		return it->second;
	}

	bool replicate_one(protocol::storage_id const& sid, storage_pulls& pulls, data_descriptor const& descriptor) {
		auto const& id = descriptor.manifest_digest;
		bool queued = false;
		if(!storable_descriptor(descriptor)) {
			LOG_WARN("asked to hold a copy of a data with a descriptor out of bounds [data_id={}] (sid={})", to_hex(id), to_hex(sid));
		} else {
			auto const have = pulls.store->open_replica(descriptor, hooks_.now());
			if(!have) {
				LOG_INFO("cannot hold a copy [data_id={}]: {} (sid={})", to_hex(id), have.get_error(), to_hex(sid));
			} else if(have.value().complete()) {
				// the record server that asked does not know: tell again
				hooks_.complete(sid, id);
			} else {
				{
					std::unique_lock lock{mutex_};
					wanted_[id] = wanted{sid, descriptor};
				}
				queued = pulls.downloader->enqueue(id);
				if(queued) {
					LOG_INFO("pulling a copy [data_id={}, held {}/{} chunks] (sid={})", to_hex(id)
						, have.value().count(), have.value().size(), to_hex(sid));
				}
			}
		}
		return queued;
	}

	/// the channel opens a download: the ticket comes from the record server that asked for the copy
	void ask_ticket(data_descriptor const& descriptor, std::move_only_function<void(util::result<data_grant>)> answer) {
		std::optional<wanted> pull;
		{
			std::unique_lock lock{mutex_};
			auto it = wanted_.find(descriptor.manifest_digest);
			if(it != wanted_.end()) {
				pull = it->second;
			}
		}
		if(pull) {
			hooks_.ticket(pull->sid, pull->descriptor, std::move(answer));
		} else {
			answer(make_error(protocol::errc::unknown_data));
		}
	}

	void on_done(protocol::storage_id const& sid, data_id const& id, std::optional<error> const& err) {
		std::shared_ptr<server_data_store> store;
		{
			std::unique_lock lock{mutex_};
			wanted_.erase(id);
			auto it = storages_.find(sid);
			if(it != storages_.end()) {
				store = it->second->store;
			}
		}
		if(err) {
			// what came is kept: the next sweep of the record server goes on from there
			LOG_INFO("pull of a copy ended [data_id={}]: {} (sid={})", to_hex(id), *err, to_hex(sid));
		} else if(store && store->replica_pulled(id, hooks_.now())) {
			LOG_INFO("copy complete [data_id={}] (sid={})", to_hex(id), to_hex(sid));
			hooks_.complete(sid, id);
		}
	}

private:
	/// a pull on its way: what the ticket is asked for
	struct wanted {
		protocol::storage_id sid;
		data_descriptor descriptor;
	};

	asio::io_context& io_;
	data_replicator_hooks const hooks_;
	data_download_config const config_;

	mutable std::mutex mutex_;
	std::map<data_id, wanted> wanted_;
	std::map<protocol::storage_id, std::shared_ptr<storage_pulls>> storages_;
	// after the maps: its callbacks look into them
	net_data_channel channel_;
};

data_replicator::data_replicator(network::context& context, data_replicator_hooks hooks, data_download_config config
	, std::chrono::seconds timeout)
: impl_(std::make_shared<impl>(context, std::move(hooks), config, timeout))
{
}

data_replicator::~data_replicator() {
	impl_->close();
}

std::size_t data_replicator::replicate(protocol::storage_id const& sid, std::vector<data_descriptor> const& descriptors) {
	return impl_->replicate(sid, descriptors);
}

std::size_t data_replicator::pending() const {
	return impl_->pending();
}

void data_replicator::close() {
	impl_->close();
}

}
