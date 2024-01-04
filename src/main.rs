mod looks;
mod parser;

use dioxus::prelude::*;

fn main() {
    dioxus_desktop::launch(App);
}

fn App(cx: Scope) -> Element {
    render!("Hello", looks::MainApp {})
}
