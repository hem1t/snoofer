pub mod logs;

use crate::{
    looks::logs::{Log, LogsView},
    parser::{ParsedPacket, Parser},
};
use dioxus::prelude::*;

#[component]
fn PacketView(cx: Scope, pckt: ParsedPacket) -> Element {
    let (a, b, c, d) = pckt.meta();
    render!(div {
        display: "block",
        "{a}, {b}, {c}, {d}"
    })
}

#[component]
pub fn MainApp(cx: Scope) -> Element {
    let parsed_packets = use_shared_state::<Vec<ParsedPacket>>(cx).unwrap();
    let parser = use_shared_state::<Parser>(cx).unwrap();
    let logger = use_shared_state::<Vec<Log>>(cx).unwrap();

    render!(
        button {
            onclick: move |_| logger.write().push(Log(String::from("Logging"))),
            "log"
        },
        LogsView {}
    )
}
