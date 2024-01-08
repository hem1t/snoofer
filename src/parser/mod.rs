#![allow(dead_code)]
mod parser_packet;

pub use parser_packet::*;
use tokio::sync::mpsc::Receiver;

use std::path::Path;
use std::{
    sync::{
        mpsc::{self, Sender},
        Arc, Mutex,
    },
    time::Duration,
};

use pcap::{Capture, Device};

pub enum ParserCommand {
    Start,
    Stop,
}

pub struct Parser {
    command_tx: Arc<Sender<ParserCommand>>,
    packet_rx: Arc<Mutex<Receiver<ParsedPacket>>>,
    packets: Vec<ParsedPacket>,
}


impl Parser {
    pub fn new_for_device(device: impl Into<Device>, filter: &str) -> Self {
        let device = device.into().clone();
        let filter = filter.to_owned();

        let (ctx, crx) = mpsc::channel::<ParserCommand>();
        let (ptx, prx) = tokio::sync::mpsc::channel::<ParsedPacket>(1);

        std::thread::spawn(move || {
            let mut capture = Capture::from_device(device).unwrap().open().unwrap();
            let _ = capture.filter(filter.as_str(), true);
            let mut file = capture.savefile("./temp.pcap").unwrap();

            'start: while let Ok(ParserCommand::Start) = crx.recv() {
                while let Ok(pac) = capture.next_packet() {
                    file.write(&pac); // write to temp
                    if let Ok(pac) = ParsedPacket::from_packet(pac) {
                        let _ = ptx.blocking_send(pac);
                    }
                    if let Ok(ParserCommand::Stop) = crx.recv_timeout(Duration::from_millis(1)) {
                        println!("Stopped listening!");
                        break 'start;
                    }
                }
            }
        });

        Self {
            packet_rx: Arc::new(Mutex::new(prx)),
            command_tx: Arc::new(ctx),
            packets: Vec::new(),
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

    pub fn save_to_file(&mut self, path: &Path) {
        // let mut file = Capture::dead(Linktype::ETHERNET)
        //     .unwrap()
        //     .savefile(path)
        //     .unwrap();
        // for pac in packets {
        //     file.write(&pac.to_packet());
        // }
        std::fs::copy("./temp.pcap", path).expect("Couldn't copy the file.");
    }
}

impl Drop for Parser {
    fn drop(&mut self) {
        let _ = std::fs::remove_file("./temp.pcap");
    }
}

#[tokio::test]
async fn parse_print_test() {
    let parser = Parser::new_for_device("wlo1", "tcp port 443");
    parser.start();
    while let Some(pac) = parser.recv().await {
        println!("{:?}", pac.meta());
    }
}
