use std::cmp::Ordering::{self, Equal, Greater, Less};
use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// A list of IP subnets. Only used to answer the question
/// "does the list contain this IpAddr", e.g. for access control.
pub struct IpList {
    list: Vec<IpNet>,
    set:  HashSet<IpAddr>,
}

impl IpList {
    /// create a new iplist
    pub fn new() -> IpList {
        IpList {
            list: Vec::new(),
            set:  HashSet::new(),
        }
    }

    /// Add a subnet
    pub fn add(&mut self, net: IpNet) {
        if net.prefix_len() == net.max_prefix_len() {
            self.set.insert(net.addr());
        } else {
            self.list.push(net.trunc());
        }
    }

    /// Call this to sort the list before using self.contains(), otherwise
    /// you will get random results.
    pub fn finalize(&mut self) {
        self.list.sort_unstable();
    }

    /// See if the list contains this IpAddr.
    pub fn contains(&self, ip: IpAddr) -> bool {
        if self.set.contains(&ip) {
            return true;
        }
        let res = match ip {
            IpAddr::V4(ip) => {
                let ipv4 = Ipv4Net::new(ip, 32).unwrap();
                self.binary_search_by(|probe| compare_v4(probe, &ipv4))
            },
            IpAddr::V6(ip) => {
                let ipv6 = Ipv6Net::new(ip, 128).unwrap();
                self.binary_search_by(|probe| compare_v6(probe, &ipv6))
            },
        };
        res.is_ok()
    }

    /// our own version of binary_search_by from the standard library.
    /// The standard lib misses an optimization, it always runs
    /// the maximum number of searches.
    #[inline]
    fn binary_search_by<'a, F>(&'a self, mut f: F) -> Result<usize, usize>
    where F: FnMut(&'a IpNet) -> Ordering {
        let s = &self.list;
        let mut size = s.len();
        if size == 0 {
            return Err(0);
        }
        let mut base = 0usize;
        while size > 1 {
            let half = size / 2;
            let mid = base + half;
            // mid is always in [0, size), that means mid is >= 0 and < size.
            // mid >= 0: by definition
            // mid < size: mid = size / 2 + size / 4 + size / 8 ...
            let cmp = f(unsafe { s.get_unchecked(mid) });
            if cmp == Equal {
                return Ok(mid);
            }; // <--- This is missing in the standard library
            base = if cmp == Greater { base } else { mid };
            size -= half;
        }
        // base is always in [0, size) because base <= mid.
        let cmp = f(unsafe { s.get_unchecked(base) });
        if cmp == Equal {
            Ok(base)
        } else {
            Err(base + (cmp == Less) as usize)
        }
    }
}

#[inline]
fn compare_v4(probe: &IpNet, ip: &Ipv4Net) -> Ordering {
    match probe {
        IpNet::V6(_) => Greater,
        IpNet::V4(probe) => {
            if probe > ip {
                Greater
            } else if probe.contains(ip) {
                Equal
            } else {
                Less
            }
        },
    }
}

#[inline]
fn compare_v6(probe: &IpNet, ip: &Ipv6Net) -> Ordering {
    match probe {
        IpNet::V4(_) => Less,
        IpNet::V6(probe) => {
            if probe > ip {
                Greater
            } else if probe.contains(ip) {
                Equal
            } else {
                Less
            }
        },
    }
}
