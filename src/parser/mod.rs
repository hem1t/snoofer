#![allow(dead_code)]
mod parser_packet;

pub use parser_packet::*;
use tokio::sync::mpsc::Receiver;

use std::{
    sync::{
        mpsc::{self, Sender},
        Arc, Mutex,
    },
    time::Duration,
};
use std::path::Path;

use pcap::{Capture, Device};

pub enum ParserCommand {
    Start,
    Stop,
}

pub struct Parser {
    command_tx: Arc<Sender<ParserCommand>>,
    packet_rx: Arc<Mutex<Receiver<ParsedPacket>>>,
    // TODO: figure out to store Packet<'a> w/o interfering with capture in parse
    //      this is required so, can store in file, after it is done parsing.
}

impl Parser {
    pub fn new_for_device(device: impl Into<Device>, filter: &str) -> Self {
        let mut capture = Capture::from_device(device).unwrap().open().unwrap();
        let _ = capture.filter(filter, true);

        let (ctx, crx) = mpsc::channel::<ParserCommand>();
        let (ptx, prx) = tokio::sync::mpsc::channel::<ParsedPacket>(1);

        std::thread::spawn(move || {
            if let Ok(ParserCommand::Start) = crx.recv() {
                while let Ok(pac) = capture.next_packet() {
                    if let Ok(pac) = ParsedPacket::from_packet(pac) {
                        let _ = ptx.blocking_send(pac);
                    }
                    if let Ok(ParserCommand::Stop) = crx.recv_timeout(Duration::from_millis(1)) {
                        break;
                    }
                }
            }
        });

        Self {
            packet_rx: Arc::new(Mutex::new(prx)),
            command_tx: Arc::new(ctx),
        }
    }

    pub fn stop(&self) {
        let _ = self.command_tx.send(ParserCommand::Stop);
    }

    pub fn start(&self) {
        let _ = self.command_tx.send(ParserCommand::Start);
    }

    pub async fn recv(&self) -> Option<ParsedPacket> {
        self.packet_rx.lock().unwrap().recv().await
    }

    pub fn save_to_file(&mut self, _path: &Path) {
        todo!()
    }
}

#[tokio::test]
async fn parse_print_test() {
    let parser = Parser::new_for_device("wlo1", "tcp port 443");
    parser.start();
    while let Some(pac) = parser.recv().await {
        println!("{:?}", pac.meta());
    }
    std::thread::sleep(Duration::from_secs(200));
}
