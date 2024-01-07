use std::time::Duration;

use crate::parser::{ParsedPacket, Parser};
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
    let parsed_packets = use_ref(cx, || Vec::<ParsedPacket>::new());
    let parser = use_ref(cx, || Parser::new_for_device("wlo1", ""));

    cx.use_hook(|| {
        cx.spawn({
            to_owned![parser];
            to_owned![parsed_packets];

            async move {
                while let Some(pac) = parser.read().recv().await {
                    println!("{:?}", pac.meta());
                    parsed_packets.write().push(pac);
                    // Not sure: if there exists better solution,
                    // but this line allows user to interact while receiving packets.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        });
    });


    let parser_start = move |_| {
        parser.read().start();
    };

    let parser_stop = move |_| {
        parser.read().stop();
    };

    let packets = parsed_packets
        .read()
        .clone()
        .into_iter()
        .map(|p| rsx!(PacketView { pckt: p.clone() }));

    render!(
        button {
            onclick: parser_start,
            "start"
        },
        button {
            onclick: parser_stop,
            "stop"
        },
        packets)
}
