#include "sync_engine.hpp"

namespace securepath::sync {

class sync_engine::impl {
public:

};

sync_engine::sync_engine(comm_input&)
: impl_(std::make_unique<impl>())
{
}

sync_engine::~sync_engine()
{
}

}
