#![allow(dead_code)]
use pcap::PacketCodec;

use pktparse::{
    ethernet::{self, EthernetFrame},
    icmp::{self, IcmpHeader},
    ip::IPProtocol,
    ipv4::{self, IPv4Header},
    ipv6::{self, IPv6Header},
    tcp::{self, TcpHeader},
    udp::{self, UdpHeader},
};

#[derive(Debug, PartialEq, Clone)]
pub enum PacketHeader {
    ICMP(IcmpHeader),
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Ipv4(IPv4Header),
    Ipv6(IPv6Header),
    Ether(EthernetFrame),
}

#[derive(Debug, PartialEq, Clone)]
pub struct ParsedPacket {
    src_ip: String,
    src_port: String,
    dest_ip: String,
    dest_port: String,
    layers: Vec<PacketHeader>,
    length: u32,
    ts: String,
}

impl PacketCodec for ParsedPacket {
    type Item = ParsedPacket;

    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        ParsedPacket::from_packet(packet).unwrap()
    }
}

impl ParsedPacket {
    pub fn new() -> Self {
        ParsedPacket {
            src_ip: String::new(),
            src_port: String::new(),
            dest_ip: String::new(),
            dest_port: String::new(),
            layers: Vec::new(),
            length: 0,
            ts: String::new(),
        }
    }

    pub fn from_packet(packet: pcap::Packet) -> Result<Self, ()> {
        Ok(ParsedPacket {
            length: packet.header.len,
            ts: format!("{}.{}", packet.header.ts.tv_sec, packet.header.ts.tv_usec),
            layers: Vec::new(),
            src_ip: String::new(),
            src_port: String::new(),
            dest_ip: String::new(),
            dest_port: String::new(),
        }
        .parse_ether(packet.data)?)
    }

    fn parse_ether(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((content, header)) = ethernet::parse_ethernet_frame(data) {
            self.layers.push(PacketHeader::Ether(header));
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
            self.layers.push(PacketHeader::Ipv4(header));
            self.src_ip = header.source_addr.to_string();
            self.dest_ip = header.dest_addr.to_string();
            return match header.protocol {
                IPProtocol::TCP => Ok(self.parse_tcp(content))?,
                IPProtocol::UDP => Ok(self.parse_udp(content))?,
                IPProtocol::ICMP => Err(()), // TODO
                _ => Err(()),
            };
        }
        Err(())
    }

    fn parse_ip6(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((content, header)) = ipv6::parse_ipv6_header(data) {
            self.layers.push(PacketHeader::Ipv6(header));
            self.src_ip = header.source_addr.to_string();
            self.dest_ip = header.dest_addr.to_string();
            return match header.next_header {
                IPProtocol::TCP => Ok(self.parse_tcp(content))?,
                IPProtocol::UDP => Ok(self.parse_udp(content))?,
                IPProtocol::ICMP => Err(()), // TODO
                _ => Err(()),
            };
        }
        Err(())
    }

    fn parse_tcp(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((_, header)) = tcp::parse_tcp_header(data) {
            self.layers.push(PacketHeader::Tcp(header.clone()));
            self.src_port = header.source_port.to_string();
            self.dest_port = header.dest_port.to_string();
            return Ok(self);
        }
        Err(())
    }

    fn parse_udp(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((_, header)) = udp::parse_udp_header(data) {
            self.layers.push(PacketHeader::Udp(header));
            self.src_port = header.source_port.to_string();
            self.dest_port = header.dest_port.to_string();
            return Ok(self);
        }
        Err(())
    }

    fn parse_icmp(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((_, header)) = icmp::parse_icmp_header(data) {
            self.layers.push(PacketHeader::ICMP(header));
            return Ok(self);
        }
        Err(())
    }

    pub fn meta(&self) -> (String, String, String, String) {
        (
            self.src_ip.clone(),
            self.dest_ip.clone(),
            self.src_port.clone(),
            self.dest_port.clone(),
        )
    }
}