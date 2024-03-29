use std::net::IpAddr;
use std::str::FromStr;

use anyhow::bail;

use super::ParsedPacket;

#[derive(PartialEq, Debug)]
pub enum Flag {
    Port(u16),
    Sport(u16),
    Dport(u16),
    Ip(IpAddr),
    Sip(IpAddr),
    Dip(IpAddr),
    ICMP,
    IP4,
    IP6,
    TCP,
    UDP,
    ETHER,
}

impl Flag {
    pub fn from_str(s: &str) -> anyhow::Result<Flag> {
        match s.to_lowercase().as_str() {
            "icmp" => Ok(Flag::ICMP),
            "ip4" => Ok(Flag::IP4),
            "ip6" => Ok(Flag::IP6),
            "tcp" => Ok(Flag::TCP),
            "udp" => Ok(Flag::UDP),
            "ether" => Ok(Flag::ETHER),
            s if s.contains('|') => {
                let mut sr = s.split('|');

                let Some(flag) = sr.next() else {
                    bail!("{s}");
                };

                let Some(val) = sr.next() else {
                    bail!("{s}");
                };

                match flag.to_lowercase().as_str() {
                    "ip" => Ok(Flag::Ip(IpAddr::from_str(val)?)),
                    "sip" => Ok(Flag::Sip(IpAddr::from_str(val)?)),
                    "dip" => Ok(Flag::Dip(IpAddr::from_str(val)?)),
                    "port" => Ok(Flag::Port(val.parse::<u16>()?)),
                    "sport" => Ok(Flag::Sport(val.parse::<u16>()?)),
                    "dport" => Ok(Flag::Dport(val.parse::<u16>()?)),
                    _ => bail!("{flag}"),
                }
            }
            _ => bail!("{s}"),
        }
    }

    pub fn to_str(&self) -> String {
        match self {
            Flag::Port(p) => format!("port|{p}"),
            Flag::Sport(p) => format!("sport|{p}"),
            Flag::Dport(p) => format!("dport|{p}"),
            Flag::Ip(ad) => format!("ip|{}", ad.to_string()),
            Flag::Sip(ad) => format!("sip|{}", ad.to_string()),
            Flag::Dip(ad) => format!("dip|{}", ad.to_string()),
            Flag::ICMP => "icmp".to_string(),
            Flag::IP4 => "ip4".to_string(),
            Flag::IP6 => "ip6".to_string(),
            Flag::TCP => "tcp".to_string(),
            Flag::UDP => "udp".to_string(),
            Flag::ETHER => "ether".to_string(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct Filter {
    signature: Vec<Flag>,
}

impl Filter {
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        let mut signature = Vec::new();
        for flag in s.split(' ').into_iter() {
            signature.push(Flag::from_str(flag)?);
        }
        Ok(Self { signature })
    }

    pub fn from_packet(pac: &ParsedPacket) -> Self {
        let mut sig = vec![
            Flag::Sip(IpAddr::from_str(&pac.src_ip).unwrap()),
            Flag::Dip(IpAddr::from_str(&pac.dest_ip).unwrap()),
            Flag::Sport(pac.src_port),
            Flag::Dport(pac.dest_port),
        ];
        sig.extend(pac.layers.iter().map(|layer| layer.to_flag()));
        Self { signature: sig }
    }

    pub fn contains(&self, flag: &Flag) -> bool {
        match flag {
            Flag::Port(p) => self.contains(&Flag::Sport(*p)) || self.contains(&Flag::Dport(*p)),
            Flag::Ip(ip) => self.contains(&Flag::Sip(*ip)) || self.contains(&Flag::Dip(*ip)),
            s => self.signature.contains(s),
        }
    }
}

impl ParsedPacket {
    pub fn contains(&self, other: &Filter) -> bool {
        let pac_sig = Filter::from_packet(&self);
        other.signature.iter().all(|flag| pac_sig.contains(flag))
    }
}

#[test]
fn str_to_filter() {
    let filter = Filter {
        signature: vec![
            Flag::ETHER,
            Flag::Sip(IpAddr::from_str("127.0.0.1").unwrap()),
            Flag::Port(443),
        ],
    };
    assert_eq!(
        Filter::from_str("ether sip|127.0.0.1 port|443").unwrap(),
        filter
    );
}
