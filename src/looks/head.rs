use dioxus::prelude::*;
use pcap::Device;

#[component]
pub fn Head(cx: Scope) -> Element {
    render! {
        // upper head to choose source
        div {
            display: "block",
            margin: "auto",
            OpenFile {},
            // OpenDevice {}
        }
        // lower head select filter and savefile
        div {
            // savefile
            input {
                r#type: "file"
            },
            input {
                r#type: "text",
                placeholder: "Filter search"
            }
            button {
                // start and stop and toggle with state
                "Start"
            }
            button {
                // Link to page, which shows help to filter.
                // TODO: use i icon
                "info"
            }
        }
    }
}

#[component]
pub fn OpenFile(cx: Scope) -> Element {
    render!(
        input {
            r#type: "file",
            font_size: "15px",
            "Select from file!"
        }
    )
}

#[component]
pub fn OpenDevice(cx: Scope) -> Element {
    let devices = Device::list().unwrap();
    let options = devices.into_iter().map(|device| {
        rsx!(
            option {
                value: "{device.name}",
                "{device.name}"
            }
        )
    });

    render! (
        select {
            id: "devices",
            name: "devices",
            required: true,
            // load options from Device::list()
            options,
        }
    )
}
