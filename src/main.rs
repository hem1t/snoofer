mod looks;
mod parser;

use looks::*;

use dioxus::prelude::*;

fn main() {
    dioxus_desktop::launch(App)
}

#[allow(non_snake_case)]
fn App(cx: Scope) -> Element {
    render!(
        style {
            include_str!("styles.css")
        }
        EntryOptionsPage{}
    )
}

#[component]
pub fn EntryOptionsPage(cx: Scope) -> Element {
    // TODO: create datalist and also list the option of devices
    render!(
        div {
            id: "entry-options-page",
            div {
                input {
                    id: "select-device-input",
                    r#type: "text",
                    placeholder: "Select from device",
                }
                button {
                    id: "select-device-proceed-button",
                    img {
                        src: "assests/proceed.png"
                    }
                }
            }
        }
    )
}
