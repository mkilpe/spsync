// SPDX-License-Identifier: MIT

#include "interface.hpp"

namespace securepath::sync {

engine_output::engine_output(event_system::event_loop& l)
: event_handler(l)
{
}

void engine_output::handle_event(std::unique_ptr<event_system::event_base> ev) {
	dispatch(*ev
			, event_dest<engine_events::on_object_data_changed>(&engine_output::on_object_data_changed)
			, event_dest<engine_events::on_user_changed>(&engine_output::on_user_changed)
			, event_dest<engine_events::on_object_conflict>(&engine_output::on_object_conflict)
			, event_dest<engine_events::on_fork_suspected>(&engine_output::on_fork_suspected)
			, event_dest<engine_events::on_equivocation>(&engine_output::on_equivocation)
			, event_dest<engine_events::on_anchor_mismatch>(&engine_output::on_anchor_mismatch)
			, event_dest<engine_events::on_record_rejected>(&engine_output::on_record_rejected)
			, event_dest<engine_events::on_data_state_changed>(&engine_output::on_data_state_changed)
			, event_dest<engine_events::on_data_transfer_failed>(&engine_output::on_data_transfer_failed)
			);
}

}
