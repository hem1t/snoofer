use crate::parser::{self, ParsedPacket, Parser};
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
    let parsed_packets = use_ref(cx, Vec::new);

    cx.spawn({
        to_owned![parsed_packets];

        async move {
            let mut parser = Parser {};
            let mut receiver = parser.parse_from_device().await;
            while let Some(pac) = receiver.recv().await {
                parsed_packets.write().push(pac);
            }
        }
    });

    let packets = parsed_packets
        .read()
        .clone()
        .into_iter()
        .map(|p| rsx!(PacketView { pckt: p.clone() }));

    render!(packets)
}
