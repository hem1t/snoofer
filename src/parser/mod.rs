#![allow(dead_code)]
mod parser_packet;

pub use parser_packet::*;

use std::path::Path;

use tokio::sync::{mpsc, mpsc::Receiver};

use pcap::Capture;

pub struct Parser {
    // TODO: store a sender to command parse tokio thread to stop
    // TODO: figure out to store Packet<'a> w/o interfering with capture in parse
}

impl Parser {
    pub async fn parse_from_device(&mut self, filter: &str) -> Receiver<ParsedPacket>{
        let mut capture = Capture::from_device("wlo1").unwrap().open().unwrap();
        let _ = capture.filter(filter, true);

        let (tx, rx) = mpsc::channel::<ParsedPacket>(10);

        tokio::spawn(async move {
            while let Ok(pac) = capture.next_packet() {
                // TODO: stop capturing when command stop is recieved.
                if let Ok(pac) = ParsedPacket::from_packet(pac) {
                    // TODO: store the packets before sending.
                    let _ = tx.send(pac).await;
                }
            }
        });

        rx
    }

    pub fn stop(&mut self) {
        todo!()
    }

    pub fn save_to_file(&mut self, _path: &Path) {
        todo!()
    }
}

#[tokio::test]
async fn parse_print_test() {
    let mut parser = Parser {};
    let mut receiver = parser.parse_from_device("").await;
    while let Some(pac) = receiver.recv().await {
        eprintln!("{:?}", pac.meta());
    }
}
