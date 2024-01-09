use std::{error::Error, fmt::Display, net::IpAddr, str::FromStr};

use super::ParsedPacket;

#[derive(Debug)]
struct FlagError;

impl Display for FlagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FlagError")
    }
}

impl Error for FlagError {}

#[derive(PartialEq, Debug)]
enum Flag {
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
    pub fn from_str(s: &str) -> Result<Flag, Box<dyn Error>> {
        match s.to_lowercase().as_str() {
            "icmp" => Ok(Flag::ICMP),
            "ip4" => Ok(Flag::IP4),
            "ip6" => Ok(Flag::IP6),
            "tcp" => Ok(Flag::TCP),
            "udp" => Ok(Flag::UDP),
            "ether" => Ok(Flag::ETHER),
            s if s.contains('|') => {
                let mut s = s.split('|');

                let Some(flag) = s.next() else {
                    return Err(Box::new(FlagError));
                };

                let Some(val) = s.next() else {
                    return Err(Box::new(FlagError));
                };

                match flag.to_lowercase().as_str() {
                    "ip" => Ok(Flag::Ip(IpAddr::from_str(val)?)),
                    "sip" => Ok(Flag::Sip(IpAddr::from_str(val)?)),
                    "dip" => Ok(Flag::Dip(IpAddr::from_str(val)?)),
                    "port" => Ok(Flag::Port(val.parse::<u16>()?)),
                    "sport" => Ok(Flag::Sport(val.parse::<u16>()?)),
                    "dport" => Ok(Flag::Dport(val.parse::<u16>()?)),
                    _ => Ok(Flag::ETHER),
                }
            }
            _ => Ok(Flag::ETHER),
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
struct Filter {
    signature: Vec<Flag>,
}

impl Filter {
    pub fn from_str(s: &str) -> Result<Self, &str> {
        let mut signature = Vec::new();
        for flag in s.split(' ').into_iter() {
            if let Ok(flag) = Flag::from_str(flag) {
                signature.push(flag);
            } else {
                return Err(flag);
            }
        }

        Ok(Self { signature })
    }

    pub fn from_packet(pac: &ParsedPacket) -> Self {
        todo!()
    }

    pub fn contains(&self, other: &Self) -> bool {
        todo!()
    }
}

#[test]
fn str_to_filter() {
    use std::str::FromStr;

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
