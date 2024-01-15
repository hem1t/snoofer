pub mod logs;
pub mod head;
pub mod packets_list;
pub mod packet_detail_window;

pub use logs::*;
pub use head::*;
pub use packets_list::*;
pub use packet_detail_window::*;

use dioxus::prelude::*;
use pcap::Device;

use crate::parser::{ParsedPacket, Parser};


#[component]
pub fn MainApp(cx: Scope) -> Element {
    // Device list
    use_shared_state_provider(cx, || Device::list().unwrap());
    // parsed_packets
    use_shared_state_provider(cx, || Vec::<ParsedPacket>::new());
    // parser
    use_shared_state_provider(cx, || {
        Parser::new_for_device(Device::lookup().unwrap().unwrap())
    });
    // logger
    use_shared_state_provider(cx, || Vec::<Log>::new());

    render!(
        style {
            //include_str!("")
        },
        Head {}
        PacketsWindow {}
        // TODO: put packetDetails and LogView in tabs
        // where packetDetails will be at default
        PacketDetailWindow {}
        LogsView {}
    )
}
