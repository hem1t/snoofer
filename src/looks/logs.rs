use dioxus::prelude::*;

pub struct Log(pub String);

#[component]
pub fn LogsView(cx: Scope) -> Element {
    let logs = use_shared_state::<Vec<Log>>(cx).unwrap();

    render!(
        div {
            background_color: "black",
            height: "500px",
            div {
                color: "white",
                for log in &*logs.read() {
                    "{log.0}" br {}
                }
            }
        }
    )
}
