#![allow(deadcode)]
use std::{
    path::Path,
    sync::{mpsc, Arc, Mutex},
    thread,
};

use pcap::{Activated, Active, Capture, Device, Offline, State};

use pktparse::{
    arp::ArpPacket,
    ethernet::{self, EthernetFrame},
    icmp::IcmpHeader,
    ip::IPProtocol,
    ipv4::{self, IPv4Header},
    ipv6::{self, IPv6Header},
    tcp::{self, TcpHeader},
    udp::{self, UdpHeader},
};

pub struct Parser<T: Activated + ?Sized> {
    packets: Vec<ParsedPacket>,
    capture: Capture<T>,
}

impl Parser<Active> {
    pub fn new_for_device() -> Self {
        Self {
            packets: Vec::new(),
            capture: Capture::from_device(Device::lookup().unwrap().unwrap())
                .unwrap()
                .open()
                .unwrap(),
        }
    }

    pub fn parse(&mut self, mut limit: usize) {
        // let (tx, rx) = mpsc::channel();
        // let packets = self.packets.clone();
        // let capture = self.capture.clone();

        // thread::spawn(move || {
        //     while let Ok(pckt) = capture.next_packet() {
        //         packets
        //             .lock()
        //             .unwrap()
        //             .push(Packet::from_packet(pckt).unwrap());
        //     }
        // });
        while let Ok(pckt) = self.capture.next_packet() {
            if limit == 0 {
                break;
            }
            limit -= 1;

            if let Ok(parsed_pckt) = ParsedPacket::from_packet(pckt) {
                self.packets.push(parsed_pckt);
            }
        }
    }

    pub fn save_to_file(&mut self, path: &Path) {
        todo!()
    }
}

#[derive(Debug)]
pub enum PacketHeader {
    ICMP(IcmpHeader),
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Ipv4(IPv4Header),
    Ipv6(IPv6Header),
    Ether(EthernetFrame),
    Arp(ArpPacket),
}

#[derive(Debug)]
pub struct ParsedPacket {
    src_ip: String,
    src_port: String,
    dest_ip: String,
    dest_port: String,
    protocol: Vec<PacketHeader>,
    length: u32,
    ts: String,
}

impl ParsedPacket {
    pub fn from_packet(packet: pcap::Packet) -> Result<Self, ()> {
        Ok(ParsedPacket {
            length: packet.header.len,
            ts: format!("{}.{}", packet.header.ts.tv_sec, packet.header.ts.tv_usec),
            protocol: Vec::new(),
            src_ip: String::new(),
            src_port: String::new(),
            dest_ip: String::new(),
            dest_port: String::new(),
        }
        .parse_ether(packet.data)?)
    }

    fn parse_ether(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((content, header)) = ethernet::parse_ethernet_frame(data) {
            self.protocol.push(PacketHeader::Ether(header));
            return match header.ethertype {
                ethernet::EtherType::IPv4 => Ok(self.parse_ip4(content))?,
                ethernet::EtherType::IPv6 => Ok(self.parse_ip6(content))?,
                _ => Err(()),
            };
        }
        Err(())
    }

    fn parse_ip4(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((content, header)) = ipv4::parse_ipv4_header(data) {
            self.protocol.push(PacketHeader::Ipv4(header));
            self.src_ip = header.source_addr.to_string();
            self.dest_ip = header.dest_addr.to_string();
            return match header.protocol {
                IPProtocol::TCP => Ok(self.parse_tcp(content))?,
                IPProtocol::UDP => Ok(self.parse_udp(content))?,
                _ => Err(()),
            };
        }
        Err(())
    }

    fn parse_ip6(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((content, header)) = ipv6::parse_ipv6_header(data) {
            self.protocol.push(PacketHeader::Ipv6(header));
            self.src_ip = header.source_addr.to_string();
            self.dest_ip = header.dest_addr.to_string();
            return match header.next_header {
                IPProtocol::TCP => Ok(self.parse_tcp(content))?,
                IPProtocol::UDP => Ok(self.parse_udp(content))?,
                _ => Err(()),
            };
        }
        Err(())
    }

    fn parse_tcp(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((content, header)) = tcp::parse_tcp_header(data) {
            self.protocol.push(PacketHeader::Tcp(header.clone()));
            self.src_port = header.source_port.to_string();
            self.dest_port = header.dest_port.to_string();
            return Ok(self);
        }
        Err(())
    }

    fn parse_udp(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((content, header)) = udp::parse_udp_header(data) {
            self.protocol.push(PacketHeader::Udp(header));
            self.src_port = header.source_port.to_string();
            self.dest_port = header.dest_port.to_string();
            return Ok(self);
        }
        Err(())
    }
}

#[test]
fn parse_print_test() {
    let mut parser = Parser::new_for_device();
    parser.parse(10);
    for pckt in parser.packets {
        eprintln!("{:?}", pckt);
    }
}
