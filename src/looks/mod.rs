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
    let parsed_packets = use_shared_state::<Vec<ParsedPacket>>(cx).unwrap();
    let parser = use_shared_state::<Parser>(cx).unwrap();

    cx.use_hook(|| {
        cx.spawn({
            to_owned![parser];
            to_owned![parsed_packets];

            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(100));
                let receiver = parser.read().get_receiver().clone();
                while let Some(pac) = receiver.lock().unwrap().recv().await {
                    println!("{:?}", pac.meta());
                    parsed_packets.write().push(pac);
                    interval.tick().await;
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
