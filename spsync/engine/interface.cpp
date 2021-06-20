#include "interface.hpp"

namespace securepath::sync {

engine_output::engine_output(event_system::event_loop_base& l)
: event_handler(l)
{
}

void engine_output::handle_event(std::unique_ptr<event_system::event_base> ev) {
	dispatch(*ev
			, event_dest<engine_events::on_object_data_changed>(&engine_output::on_object_data_changed)
			, event_dest<engine_events::on_user_changed>(&engine_output::on_user_changed)
			);
}

}
