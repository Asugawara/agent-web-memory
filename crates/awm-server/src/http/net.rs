//! The client address of a request (`docs/sync-v1.md` §12, plan-v3-team §4.10): the socket's
//! peer, or `X-Forwarded-For` only when the peer is a trusted proxy.

use std::net::IpAddr;
use std::str::FromStr;

/// An address range: `10.0.0.0/8`, `2001:db8::/32`, or a single host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// `None` when the prefix is longer than the address.
    pub fn new(addr: IpAddr, prefix: u8) -> Option<IpNet> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(IpNet { addr, prefix })
    }

    pub fn host(addr: IpAddr) -> IpNet {
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        IpNet { addr, prefix }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr.to_canonical(), ip.to_canonical()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                masked(u128::from(u32::from(a)), 32, self.prefix_in(32))
                    == masked(u128::from(u32::from(b)), 32, self.prefix_in(32))
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                masked(u128::from(a), 128, self.prefix) == masked(u128::from(b), 128, self.prefix)
            }
            _ => false,
        }
    }

    /// The prefix as a length in a `bits`-bit address (a v4-mapped v6 range keeps its v4 part).
    fn prefix_in(&self, bits: u8) -> u8 {
        if self.addr.is_ipv4() || bits == 128 {
            self.prefix
        } else {
            self.prefix.saturating_sub(96)
        }
    }
}

fn masked(v: u128, bits: u8, prefix: u8) -> u128 {
    let prefix = prefix.min(bits);
    if prefix == 0 {
        return 0;
    }
    let shift = u32::from(bits - prefix);
    (v >> shift) << shift
}

impl FromStr for IpNet {
    type Err = String;

    fn from_str(s: &str) -> Result<IpNet, String> {
        let bad = || format!("not an address range: {s:?}");
        match s.split_once('/') {
            None => s.parse().map(IpNet::host).map_err(|_| bad()),
            Some((a, p)) => {
                let addr: IpAddr = a.parse().map_err(|_| bad())?;
                let prefix: u8 = p.parse().map_err(|_| bad())?;
                IpNet::new(addr, prefix).ok_or_else(bad)
            }
        }
    }
}

/// The address a request's limits are keyed on.
///
/// With a peer outside `trusted` the header is ignored (anyone can send it). With a trusted
/// peer, the entries of `X-Forwarded-For` are read from the right, skipping trusted proxies; the
/// first other entry is the client. An unparsable entry ends the walk at the socket's peer.
pub fn client_ip(peer: IpAddr, forwarded_for: Option<&str>, trusted: &[IpNet]) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|n| n.contains(ip));
    if !is_trusted(peer) {
        return peer;
    }
    let Some(header) = forwarded_for else {
        return peer;
    };
    let mut leftmost = None;
    for entry in header.rsplit(',') {
        let Ok(ip) = entry.trim().parse::<IpAddr>() else {
            return peer;
        };
        if !is_trusted(ip) {
            return ip;
        }
        leftmost = Some(ip);
    }
    leftmost.unwrap_or(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn ranges_contain_their_addresses() {
        assert!(net("10.0.0.0/8").contains(ip("10.9.8.7")));
        assert!(!net("10.0.0.0/8").contains(ip("11.0.0.1")));
        assert!(net("192.0.2.1").contains(ip("192.0.2.1")));
        assert!(!net("192.0.2.1").contains(ip("192.0.2.2")));
        assert!(net("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(net("2001:db8::/32").contains(ip("2001:db8:1::1")));
        assert!(!net("2001:db8::/32").contains(ip("2001:db9::1")));
        assert!(net("10.0.0.0/8").contains(ip("::ffff:10.1.2.3")));
        assert!("10.0.0.0/33".parse::<IpNet>().is_err());
        assert!("nope".parse::<IpNet>().is_err());
    }

    #[test]
    fn the_header_counts_only_behind_a_trusted_peer() {
        let trusted = [net("10.0.0.0/8")];
        let peer = ip("203.0.113.5");
        assert_eq!(client_ip(peer, Some("198.51.100.7"), &trusted), peer);
        assert_eq!(client_ip(peer, Some("198.51.100.7"), &[]), peer);
        let proxy = ip("10.1.1.1");
        assert_eq!(
            client_ip(proxy, Some("198.51.100.7"), &trusted),
            ip("198.51.100.7")
        );
        // A client-supplied left part cannot be chosen: the right-most untrusted entry wins.
        assert_eq!(
            client_ip(proxy, Some("1.2.3.4, 198.51.100.7, 10.2.2.2"), &trusted),
            ip("198.51.100.7")
        );
        assert_eq!(client_ip(proxy, None, &trusted), proxy);
        assert_eq!(client_ip(proxy, Some("garbage"), &trusted), proxy);
        assert_eq!(client_ip(proxy, Some("10.5.5.5"), &trusted), ip("10.5.5.5"));
    }
}
