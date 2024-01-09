mod looks;
mod parser;

use dioxus::prelude::*;
use pcap::Device;

use crate::parser::{ParsedPacket, Parser};

fn main() {
    dioxus_desktop::launch(App);
}

#[allow(non_snake_case)]
fn App(cx: Scope) -> Element {
    use_shared_state_provider(cx, || Vec::<ParsedPacket>::new());
    use_shared_state_provider(cx, || {
        Parser::new_for_device(Device::lookup().unwrap().unwrap())
    });
    render!("Hello", looks::MainApp {})
}
