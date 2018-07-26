
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
    pub map:        HashMap<String, MapOrMaps>,
    #[serde(skip)]
    pub map_:       HashMap<String, Vec<Map>>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Server {
    pub listen:     OneOrManyAddr,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Domain {
    pub name:       String,
    pub db_dir:     String,
    pub maps:       Vec<String>,
    #[serde(default,rename = "default")]
    pub is_default: bool,
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
    Ok(config)
}

