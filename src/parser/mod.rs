#![allow(dead_code)]
mod filter;
mod parser_packet;

pub use parser_packet::*;
use tokio::sync::mpsc::Receiver;

use std::path::{Path, PathBuf};
use std::{
    sync::{
        mpsc::{self, Sender},
        Arc, Mutex,
    },
    time::Duration,
};

use pcap::{Capture, Device};

pub struct ParserSelector {
    parser: Option<Parser>,
}

impl ParserSelector {
    pub fn new() -> Self {
        Self { parser: None }
    }

    pub fn select_file(&mut self, path: &PathBuf) {
        self.parser = Some(Parser::new_from_file(&path));
    }

    pub fn select_device(&mut self, dev_name: &str) {
        self.parser = Some(Parser::new_for_device(dev_name));
    }

    pub fn is_parser_avail(&self) -> bool {
        dbg!(self.parser.is_some())
    }
}

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
    pub fn new_for_device(device: impl Into<Device>) -> Self {
        let mut capture = Capture::from_device(device).unwrap().open().unwrap();
        let mut file = capture.savefile("./temp.pcap").unwrap();

        let (ctx, crx) = mpsc::channel::<ParserCommand>();
        let (ptx, prx) = tokio::sync::mpsc::channel::<ParsedPacket>(1);

        std::thread::spawn(move || {
            if let Ok(ParserCommand::Start) = crx.recv() {
                println!("Received Start Signal!");
                while let Ok(pac) = capture.next_packet() {
                    file.write(&pac); // write to temp
                    if let Ok(pac) = ParsedPacket::from_packet(pac) {
                        let _ = ptx.blocking_send(pac);
                    }
                    if let Ok(ParserCommand::Stop) = crx.recv_timeout(Duration::from_millis(1)) {
                        println!("Received stop signal!");
                        break;
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

    pub fn new_from_file(path: &Path) -> Self {
        let mut capture = Capture::from_file(path).unwrap();

        let (ctx, crx) = mpsc::channel::<ParserCommand>();
        let (ptx, prx) = tokio::sync::mpsc::channel::<ParsedPacket>(1);

        std::thread::spawn(move || {
            'start: while let Ok(ParserCommand::Start) = crx.recv() {
                while let Ok(pac) = capture.next_packet() {
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

    pub fn get_receiver(&self) -> Arc<Mutex<Receiver<ParsedPacket>>> {
        self.packet_rx.clone()
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
    let parser = Parser::new_for_device("wlo1");
    parser.start();
    let receiver = parser.get_receiver();
    while let Some(pac) = receiver.lock().unwrap().recv().await {
        println!("{:?}", pac.meta());
    }
}
