
use std;
use std::io::prelude::*;
use std::io;
use std::fs::File;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use toml;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub server:     Server,
    pub domain:     Vec<Domain>,
    #[serde(default)]
    pub map:        HashMap<String, MapOrMaps>,
    #[serde(skip)]
    pub map_:       HashMap<String, Vec<Map>>,
    #[serde(default)]
    pub auth:       HashMap<String, Auth>,
    #[serde(default)]
    pub shells:     HashMap<String, Shells>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Server {
    #[serde(default)]
    pub tls:            bool,
    pub p12_file:       Option<String>,
    pub crt_file:       Option<String>,
    pub key_file:       Option<String>,
    #[serde(default)]
    pub cert_password:  String,
    pub listen:         OneOrManyAddr,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Domain {
    /// domain name
    pub name:       String,
    /// database directory
    pub db_dir:     String,
    /// available (allowed) maps
    pub maps:       Vec<String>,
    /// link to the authentication method/map
    pub auth:       Option<String>,
    /// password needed to allow access to this domain
    pub password:   Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Auth {
    pub map:            String,
    pub key:            String,
    #[serde(default)]
    pub shells:         String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Shells {
    #[serde(default)]
    pub allow:          Vec<String>,
    #[serde(default)]
    pub deny:           Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Map {
    pub key:        Option<String>,
    #[serde(default)]
    pub keys:       Vec<String>,
    #[serde(default)]
    pub key_alias:  HashMap<String, String>,
    pub map_format: Option<String>,
    pub map_type:   String,
    pub map_file:   String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum MapOrMaps {
    Map(Map),
    Maps(HashMap<String, Map>),
}

#[derive(Deserialize,Debug,Clone)]
#[serde(untagged)]
pub enum OneOrManyAddr {
    One(SocketAddr),
    Many(Vec<SocketAddr>),
}

impl ToSocketAddrs for OneOrManyAddr {
    type Iter = std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> io::Result<std::vec::IntoIter<SocketAddr>> {
        let i = match self {
            OneOrManyAddr::Many(ref v) => v.to_owned(),
            OneOrManyAddr::One(ref s) => vec![*s],
        };
        Ok(i.into_iter())
    }
}

pub fn read(name: &str) -> io::Result<Config> {
    let mut f = File::open(name)?;
    let mut buffer = String::new();
    f.read_to_string(&mut buffer)?;

    let mut config : Config = match toml::from_str(&buffer) {
        Ok(v) => Ok(v),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }?;
    for (k, v) in config.map.iter() {
        let mut mm = Vec::new();
        match v {
            MapOrMaps::Map(m) => mm.push(m.to_owned()),
            MapOrMaps::Maps(m) => mm.extend(m.values().map(|v| v.to_owned())),
        }
        config.map_.insert(k.to_string(), mm);
    }

    if config.server.tls {
        if config.server.p12_file.is_none() && config.server.key_file.is_none() && config.server.crt_file.is_none() {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                                           "config: tls enabled but no cert files configured"));
        }

        if config.server.p12_file.is_some() {
            if config.server.key_file.is_some() || config.server.crt_file.is_some() {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                                           "config: set either p12 or pem (key/crt) certs, not both"));
            }
        }

        if config.server.key_file.is_some() || config.server.crt_file.is_some() {
            if config.server.key_file.is_some() != config.server.crt_file.is_some() {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                                           "config: both the key_file and crt_file must be set"));
            }
        }
    }

    Ok(config)
}

impl Config {

    /// look up a domain by name.
    pub fn find_domain(&self, name: &str) -> Option<&Domain> {
        self.domain.iter().find(|d| d.name == name)
    }

    /// Find a map by name. As map definitions with the same name can occur
    /// multiple times in the config with different keys, the key has
    /// to be a valid lookup key for the map as well.
    pub fn find_map<'a>(&self, mapname: &str, key: &str) -> Option<(&Map, &str)> {
        let maps = self.map_.get(mapname)?;
        for m in maps {
            let key = m.key_alias.get(key).map(|s| s.as_str()).unwrap_or(key);
            let mut keys= m.key.iter().chain(m.keys.iter());
            if let Some(k) = keys.find(|ref k| k.as_str() == key) {
                return Some((m, k));
            }
        }
        None
    }

    /// Like find_map, but map must be in the allowed list for the domain
    pub fn find_allowed_map(&self, domain: &Domain, mapname: &str, key: &str) -> Option<(&Map, &str)> {
        domain.maps.iter().find(|m| m.as_str() == mapname)
            .and_then(|_| self.find_map(mapname, key))
    }
}
