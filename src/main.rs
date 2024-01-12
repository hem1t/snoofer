mod looks;
mod parser;

use dioxus::prelude::*;
use pcap::Device;

use crate::{
    looks::logs::Log,
    parser::{ParsedPacket, Parser},
};

fn main() {
    dioxus_desktop::launch(App)
}

#[allow(non_snake_case)]
fn App(cx: Scope) -> Element {
    // parsed_packets
    use_shared_state_provider(cx, || Vec::<ParsedPacket>::new());
    // parser
    use_shared_state_provider(cx, || {
        Parser::new_for_device(Device::lookup().unwrap().unwrap())
    });
    // logger
    use_shared_state_provider(cx, || Vec::<Log>::new());

    render!("Hello", looks::MainApp {})
}
