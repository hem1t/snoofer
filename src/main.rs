mod looks;
mod parser;

use dioxus::prelude::*;

fn main() {
    dioxus_desktop::launch(App);
}

#[allow(non_snake_case)]
fn App(cx: Scope) -> Element {
    render!("Hello", looks::MainApp {})
}
