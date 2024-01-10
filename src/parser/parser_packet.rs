#![allow(dead_code)]

use pktparse::{
    ethernet::{self, EthernetFrame},
    icmp::{self, IcmpHeader},
    ip::IPProtocol,
    ipv4::{self, IPv4Header},
    ipv6::{self, IPv6Header},
    tcp::{self, TcpHeader},
    udp::{self, UdpHeader},
};

use crate::parser::filter::*;

#[derive(Debug, PartialEq, Clone)]
pub enum PacketHeader {
    ICMP(IcmpHeader),
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Ipv4(IPv4Header),
    Ipv6(IPv6Header),
    Ether(EthernetFrame),
}

impl PacketHeader {
    pub fn to_flag(&self) -> Flag {
        match self {
            PacketHeader::ICMP(_) => Flag::ICMP,
            PacketHeader::Tcp(_) => Flag::TCP,
            PacketHeader::Udp(_) => Flag::UDP,
            PacketHeader::Ipv4(_) => Flag::IP4,
            PacketHeader::Ipv6(_) => Flag::IP6,
            PacketHeader::Ether(_) => Flag::ETHER,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ParsedPacket {
    pub src_ip: String,
    pub src_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
    pub layers: Vec<PacketHeader>,
    pub length: u32,
    pub ts: String,
    // data: Vec<u8>,
    // packet_header: pcap::PacketHeader,
}

impl ParsedPacket {
    pub fn from_packet(packet: pcap::Packet) -> Result<Self, ()> {
        Ok(ParsedPacket {
            length: packet.header.len,
            ts: format!("{}.{}", packet.header.ts.tv_sec, packet.header.ts.tv_usec),
            layers: Vec::new(),
            src_ip: String::new(),
            src_port: 0,
            dest_ip: String::new(),
            dest_port: 0,
            // data: packet.data.to_vec(),
            // packet_header: *packet.header,
        }
        .parse_ether(packet.data)?)
    }

    // pub fn to_packet<'a>(&'a self) -> pcap::Packet<'a> {
    //     pcap::Packet::new(&self.packet_header, &self.data)
    // }

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
                IPProtocol::TCP => Ok(self.parse_tcp(content)?),
                IPProtocol::UDP => Ok(self.parse_udp(content)?),
                IPProtocol::ICMP => Ok(self.parse_icmp(content)?), // TODO
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
                IPProtocol::TCP => Ok(self.parse_tcp(content)?),
                IPProtocol::UDP => Ok(self.parse_udp(content)?),
                IPProtocol::ICMP => Ok(self.parse_icmp(content)?), // TODO
                _ => Err(()),
            };
        }
        Err(())
    }

    fn parse_tcp(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((_, header)) = tcp::parse_tcp_header(data) {
            self.layers.push(PacketHeader::Tcp(header.clone()));
            self.src_port = header.source_port;
            self.dest_port = header.dest_port;
            return Ok(self);
        }
        Err(())
    }

    fn parse_udp(mut self, data: &[u8]) -> Result<Self, ()> {
        if let Ok((_, header)) = udp::parse_udp_header(data) {
            self.layers.push(PacketHeader::Udp(header));
            self.src_port = header.source_port;
            self.dest_port = header.dest_port;
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

    pub fn meta(&self) -> (String, String, u16, u16) {
        (
            self.src_ip.clone(),
            self.dest_ip.clone(),
            self.src_port,
            self.dest_port,
        )
    }
}

#[tokio::test]
async fn test_filter() {
    let parser = crate::parser::Parser::new_for_device("wlo1");
    let mut parsed_packets = Vec::new();
    let filter = Filter::from_str("port|443 ether").unwrap();

    parser.start();
    let receiver = parser.get_receiver();
    eprintln!("Starting");
    for i in 0..10 {
        eprintln!("Waiting for {}", i);
        if let Some(parsed_packet) = receiver.lock().unwrap().recv().await {
            eprintln!("Captured: {:?}", Filter::from_packet(&parsed_packet));
            parsed_packets.push(parsed_packet);
        }
        eprintln!("Received {}", i);
    }
    eprintln!("Captured ten");
    parser.stop();
    // parser.stop() print in between! Since running on different thread
    std::thread::sleep(std::time::Duration::from_millis(1));

    for pac in parsed_packets {
        if pac.contains(&filter) {
            eprintln!("{:?}", pac.meta());
        }
    }
}
