#include "interface.hpp"

namespace securepath::sync {

comm_output::comm_output(event_system::event_loop_base& l)
: event_handler(l)
{
}

void comm_output::handle_event(std::unique_ptr<event_system::event_base> ev) {
	dispatch(*ev
			, event_dest<comm_events::on_record_received>(&comm_output::on_record_received)
			, event_dest<comm_events::on_commit_response>(&comm_output::on_commit_response)
			, event_dest<comm_events::on_data_response>(&comm_output::on_data_response)
			, event_dest<comm_events::on_data_uploaded>(&comm_output::on_data_uploaded)
			, event_dest<comm_events::on_sequence_number_response>(&comm_output::on_sequence_number_response)
			, event_dest<comm_events::on_connected>(&comm_output::on_connected)
			, event_dest<comm_events::on_disconnected>(&comm_output::on_disconnected)
			);
}

}
