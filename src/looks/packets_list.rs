use dioxus::prelude::*;

#[component]
pub fn PacketsWindow(cx: Scope) -> Element {
    render!(
        div {
            height: "600px",
            for _ in 0..8 {
                PacketMeta {}
            }
        }
    )
}

#[component]
fn PacketMeta(cx: Scope) -> Element {
    render!(
        "print packet meta"
    )
}
