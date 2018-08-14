
use std;
use std::io;
use std::path::{Path, PathBuf};
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
    pub lua:        Option<LuaConfig>,
    pub include_maps:   Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Server {
    #[serde(default)]
    pub tls:            bool,
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
    pub map:            Option<String>,
    pub key:            Option<String>,
    pub lua_function:   Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Map {
    #[serde(skip, default)]
    pub name:       String,
    pub key:        Option<String>,
    #[serde(default)]
    pub keys:       Vec<String>,
    #[serde(default)]
    pub key_alias:  HashMap<String, String>,
    /// LUA function to call.
    pub lua_function: Option<String>,
    /// type: gdbm, json, lua
    pub map_type:   String,
    /// format: kv, json, passwd, fields (optional for map_type "json")
    pub map_format: Option<String>,
    /// filename
    pub map_file:   Option<String>,
    /// optional args for types like 'fields'
    pub map_args:   Option<HashMap<String, String>>,
    /// override map for this map.
    pub map_override: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LuaConfig {
    pub script:         String,
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

pub fn read(toml_file: impl AsRef<Path>) -> io::Result<Config> {
    let buffer = std::fs::read_to_string(&toml_file)?;

    let mut config : Config = match toml::from_str(&buffer) {
        Ok(v) => Ok(v),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }?;

    if let Some(ref extra) = config.include_maps {
        let include_maps = match toml_file.as_ref().parent() {
            Some(parent) => parent.join(Path::new(extra)),
            None => PathBuf::from(extra),
        };
        let buffer = std::fs::read_to_string(&include_maps)
            .map_err(|e| io::Error::new(e.kind(), format!("{:?}: {}", include_maps, e)))?;
        let maps : HashMap<String, MapOrMaps> = match toml::from_str(&buffer) {
            Ok(v) => Ok(v),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData,
                                    format!("include_maps {:?}: {}", include_maps, e))),
        }?;
        for (name, map) in maps.into_iter() {
            config.map.insert(name, map);
        }
    }

    // Build the `map_ `HashMap.
    for (k, v) in config.map.iter() {
        let mut mm = Vec::new();
        match v {
            MapOrMaps::Map(m) => mm.push(m.to_owned()),
            MapOrMaps::Maps(m) => mm.extend(m.values().map(|v| v.to_owned())),
        }
        for m in &mut mm {
            m.name = k.to_string();
            if m.lua_function.is_some() {
                if m.map_type != "lua" {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                                    format!("map {}: lua_function set, map_type must be \"lua\"", m.name)));
                }
            } else {
                if m.map_file.is_none() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                                    format!("map {}: map_file not set", m.name)));
                }
            }
        }
        config.map_.insert(k.to_string(), mm);
    }

    // Check domains for validity
    for d in &config.domain {
        if let Some(ref auth_name) = d.auth {
            let auth = match config.auth.get(auth_name) {
                None => return Err(io::Error::new(io::ErrorKind::InvalidData,
                                   format!("config: domain {}: auth {} not defined", d.name, auth_name))),
                Some(a) => a,
            };
            if auth.lua_function.is_none() {
                if auth.key.is_none() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                           format!("config: auth {}: 'key' not set", auth_name)));
                }
                if auth.map.is_none() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                           format!("config: auth {}: 'map' not set", auth_name)));
                }
            }
        }
    }

    // Check if TLS settings are valid.
    if config.server.tls {
        if config.server.key_file.is_none() && config.server.crt_file.is_none() {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                                           "config: tls enabled but no cert files configured"));
        }

        if config.server.key_file.is_some() != config.server.crt_file.is_some() {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                       "config: both the key_file and crt_file must be set"));
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
