#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;
use std::net::IpAddr;

pub struct NetworkSourceVerifier {
    allowed_networks: Vec<String>,
}

impl NetworkSourceVerifier {
    #[must_use]
    pub fn new(allowed_networks: Vec<String>) -> Self {
        Self { allowed_networks }
    }

    pub fn is_allowed(&self, source_ip: IpAddr) -> Result<bool> {
        for cidr in &self.allowed_networks {
            if ip_in_cidr(source_ip, cidr) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return match ip {
            IpAddr::V4(v4) => cidr.parse::<std::net::Ipv4Addr>().is_ok_and(|a| a == v4),
            IpAddr::V6(v6) => cidr.parse::<std::net::Ipv6Addr>().is_ok_and(|a| a == v6),
        };
    }

    let prefix_len: u32 = parts[1].parse().unwrap_or(0);

    match ip {
        IpAddr::V4(v4) => {
            if let Ok(network) = parts[0].parse::<std::net::Ipv4Addr>() {
                let ip_bits = u32::from(v4);
                let net_bits = u32::from(network);
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix_len)
                };
                return (ip_bits & mask) == (net_bits & mask);
            }
            false
        }
        IpAddr::V6(v6) => {
            if let Ok(network) = parts[0].parse::<std::net::Ipv6Addr>() {
                let ip_bits = u128::from(v6);
                let net_bits = u128::from(network);
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix_len)
                };
                return (ip_bits & mask) == (net_bits & mask);
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_single_ip_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.1".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(v.is_allowed(ip).unwrap());
    }

    #[test]
    fn test_single_ip_no_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.1".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!v.is_allowed(ip).unwrap());
    }

    #[test]
    fn test_cidr_24_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.0/24".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(v.is_allowed(ip).unwrap());
    }

    #[test]
    fn test_cidr_24_no_match() {
        let v = NetworkSourceVerifier::new(vec!["192.168.1.0/24".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1));
        assert!(!v.is_allowed(ip).unwrap());
    }

    #[test]
    fn test_cidr_16() {
        let v = NetworkSourceVerifier::new(vec!["10.0.0.0/16".to_string()]);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 255, 255));
        assert!(v.is_allowed(ip).unwrap());
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0));
        assert!(!v.is_allowed(ip2).unwrap());
    }

    #[test]
    fn test_ipv6() {
        let v = NetworkSourceVerifier::new(vec!["::1/128".to_string()]);
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(v.is_allowed(ip).unwrap());
    }

    #[test]
    fn test_empty_allowed() {
        let v = NetworkSourceVerifier::new(vec![]);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(!v.is_allowed(ip).unwrap());
    }
}
