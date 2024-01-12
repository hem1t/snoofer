use dioxus::prelude::*;

#[component]
pub fn Head(cx: Scope) -> Element {
    render! {
        // upper head to choose source
        div {
            display: "block",
            OpenFile {},
            OpenDevice {}
        }
        // lower head select filter and savefile
        div {
            // savefile
            input {
                r#type: "file"
            }
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
        button {
            "Select from file!"
        }
    )
}

#[component]
pub fn OpenDevice(cx: Scope) -> Element {
    render! (
        select {
            name: "Devices",
            required: true,
            // load options from Device::list()
            option {
                value: "wlo1",
            },
            option {
                value: "file",
            }
        }
    )
}
