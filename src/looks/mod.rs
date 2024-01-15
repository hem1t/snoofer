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

use crate::parser::ParserSelector;


#[component]
pub fn MainApp(cx: Scope) -> Element {
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

#[component]
pub fn EntryOptionsPage(cx: Scope) -> Element {
    let parser = use_shared_state::<ParserSelector>(cx).unwrap();
    let def_device = Device::lookup().unwrap().unwrap();
    let msg = use_state(cx, || "");

    render!(
        style {
            include_str!("styles/entry_page.css")
        },
        div {

            id: "entry-options-page",
            div {
                id: "entry-page-msg",
                "{msg}"
            },
            label { "Select the source: " },
            button {
                class: "option-button",
                onclick: move |_| {
                    if let Some(file) = rfd::FileDialog::new().add_filter("Pcap files: ", &["pcap"]).pick_file() {
                        parser.write().select_file(&file.to_path_buf());
                    } else {
                        msg.set("Warn invalid file or file not selected");
                    }
                },
                "Select from file"
            },
            button {
                class: "option-button",
                onclick: move |_| {
                    parser.write().select_device(&def_device.name);
                },
                div {
                    id: "device-option-label",
                    label {"Open device: "},
                    label {
                        class: "device-name",
                        "{def_device.name}"
                    }
                }
            }
        }
    )
}
