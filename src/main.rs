mod looks;
mod parser;

use looks::*;

use dioxus::prelude::*;

use crate::parser::ParserSelector;

fn main() {
    dioxus_desktop::launch(App)
}

#[allow(non_snake_case)]
fn App(cx: Scope) -> Element {
    use_shared_state_provider(cx, || ParserSelector::new());
    let parser_selector = use_shared_state::<ParserSelector>(cx).unwrap();

    let page = if parser_selector.read().is_parser_avail() {
        rsx!(MainApp {})
    } else {
        rsx!(EntryOptionsPage {})
    };

    render!(
        style {
            include_str!("styles/main.css")
        },
        page
    )
}

