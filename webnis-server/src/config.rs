
use std::io;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, IpAddr};
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::{Ipv4Net,Ipv6Net,IpNet};
use toml;

use crate::db::{MapType, deserialize_map_type};
use crate::iplist::IpList;
use crate::format::{Format, option_deserialize_format};

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub server:     Server,
    pub domain:     Vec<Domain>,
    //#[serde(default, rename="mapdef")]
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
    #[serde(default)]
    pub securenets: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Domain {
    /// domain name
    pub name:               String,
    /// database directory
    pub db_dir:             String,
    /// available (allowed) maps
    pub maps:               Vec<String>,
    /// link to the authentication method/map
    pub auth:               Option<String>,
    /// HTTP Authentication schema (first thing in the Authorization: header)
    pub http_authschema:    Option<String>,
    /// HTTP Token (comes after the schema in the Authorization header).
    pub http_authtoken:     Option<String>,
    /// Encoding of the authtoken. For schema 'Basic' this is usually 'base64'.
    pub http_authencoding:  Option<String>,
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
    #[serde(default, rename = "type", deserialize_with = "deserialize_map_type")]
    pub map_type:   MapType,
    /// format: kv, json, passwd, fields (optional for map_type "json")
    #[serde(default, rename = "format", deserialize_with = "option_deserialize_format")]
    pub map_format: Option<Format>,
    /// filename
    #[serde(rename = "file")]
    pub map_file:   Option<String>,
    /// optional args for types like 'fields'
    #[serde(rename = "output")]
    pub map_output:   Option<HashMap<String, String>>,
    #[serde(flatten)]
    pub submaps:    HashMap<String, Map>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LuaConfig {
    pub script:         String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum MapOrMaps {
    Maps(HashMap<String, Map>),
    Map(Map),
//    Other(serde_json::Value),
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

fn map_inherit(key: &str, map: &Map, base: &Map) -> Map {
    Map {
        name:           String::new(),
        key:            map.key.clone().or_else(|| Some(key.to_string())),
        keys:           map.keys.clone(),
        key_alias:      map.key_alias.clone(),
        lua_function:   map.lua_function.clone().or_else(|| base.lua_function.clone()),
        map_type:       if map.map_type != MapType::None { map.map_type.clone() } else { base.map_type.clone() },
        map_format:     map.map_format.clone().or_else(|| base.map_format.clone()),
        map_file:       map.map_file.clone().or_else(|| base.map_file.clone()),
        map_output:     map.map_output.clone().or_else(|| base.map_output.clone()),
        submaps:        HashMap::new(),
    }
}

// Read the TOML config into a config::Condig struct.
pub fn read(toml_file: impl AsRef<Path>) -> io::Result<Config> {
    let buffer = std::fs::read_to_string(&toml_file)?;

    // initial parse.
    let mut config : Config = match toml::from_str(&buffer) {
        Ok(v) => Ok(v),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }?;

    // see if "include_maps" is set- if so, read a separate map definition file.
    if let Some(ref extra) = config.include_maps {
        // relative to main config file.
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
        // add to main config.
        for (name, map) in maps.into_iter() {
            config.map.insert(name, map);
        }
    }
    // Build the `map_ `HashMap.
    for (k, v) in config.map.iter() {
        //
        // there are 3 variants here:
        //
        // 1. simple map definition: [passwd] => MapOrMaps::Map( MapDef )
        //
        // 2. a map definition with the keyname included in the name.
        //    There can be multiple definitions with the same basename.
        //    E.g [passwd.name] and [passwd.uid] => MapOrMaps::Maps( HashMap<String, Map> )
        //    The hashmap has two entries here, with keys "name" and "uid".
        //
        // 3. Like 2, but with a basemap definition.
        //    E.g [passwd], [passwd.name], [passwd.uid].
        //    This results in a single Map (MapOrMaps::Map), where the
        //    passwd.name and passwd.uid maps can be found in the map.submaps member.
        //
        // We put all definitions with the same basename together in a Vec.
        let mut mm = Vec::new();
        match v {
            MapOrMaps::Map(m) => {
                if m.submaps.len() > 0 {
                    // basemap with submaps.
                    if m.key.is_some() || m.keys.len() > 0 || m.key_alias.len() > 0 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData,
                                    format!("map {}: basemap cannot have a key", k)));
                    }
                    for (key, submap) in m.submaps.iter() {
                        mm.push(map_inherit(key, submap, m));
                    }
                } else {
                    // single map.
                    mm.push(m.to_owned());
                }
            },
            MapOrMaps::Maps(m) => {
                for (key, map) in m.iter() {
                    let mut newmap = map.clone();
                    if newmap.key.is_none() {
                        newmap.key = Some(key.to_owned());
                    }
                    mm.push(newmap);
                }
            },
        }

        // Now walk over all maps and do some basic validity checks.
        for m in &mut mm {
            m.name = k.to_string();

            // Map type must be set.
            if m.map_type == MapType::None {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                                    format!("map {}: map_type not set", m.name)));
            }

            // format = "..." only works with MapType::Gdbm at this time.
            if m.map_type != MapType::Gdbm && m.map_format.is_some() {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                            format!("map {}: cannot use format with map type {:?}", m.name, m.map_type)));
            }

            if m.map_type == MapType::Lua {
                // Type Lua, function must be set.
                if m.lua_function.is_none() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                                format!("map {}: lua_function not set", m.name)));
                }
            } else {
                // lua_function must not be set.
                if m.lua_function.is_some() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                                format!("map {}: lua_function set, map_type must be \"lua\"", m.name)));
                }

                // Must have a key.
                if m.key.is_none() && m.keys.len() == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                                format!("map {}: no key", m.name)));
                }

                // Must have a filename.
                if m.map_file.is_none() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                                format!("map {}: map file not set", m.name)));
                }

                // output mapping doesn't work (yet) with all formats.
                if m.map_output.is_some() {
                    match m.map_format {
                        | Some(Format::Json)
                        | Some(Format::Passwd)
                        | Some(Format::Group)
                        | Some(Format::Adjunct) => {
                            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                format!("map {}: cannot use output with format {:?}", m.name, m.map_format)));
                        },
                        _ => {},
                    }
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
    pub fn find_map<'b, 'a: 'b>(&'a self, mapname: &str, key: &'b str) -> Option<(&'a Map, &'b str)> {
        let maps = self.map_.get(mapname)?;

        // if it's just one map without any keys, return map.
        // this can only happen for LUA maps.
        if maps.len() == 1 && maps[0].key.is_none() && maps[0].keys.len() == 0 {
            return Some((&maps[0], key));
        }

        // find first map with a matching key.
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
    pub fn find_allowed_map<'b, 'a: 'b>(&'a self, domain: &Domain, mapname: &str, key: &'b str) -> Option<(&'a Map, &'b str)> {
        domain.maps.iter().find(|m| m.as_str() == mapname)
            .and_then(|_| self.find_map(mapname, key))
    }
}

fn masklen(mask: &Ipv4Addr) -> u8 {
    let v : u32 = (*mask).into();
    for i in 0..32 {
        if v & 2u32.pow(i) > 0 {
            return (32 - i) as u8;
        }
    }
    0
}

/// parse IP adress/mask, 2 formats:
/// 1. 255.255.255.248 194.109.16.0
/// 2. 194.109.16.0/27 or 2001:888:4:42::/64
fn parse_ip(words: Vec<&str>) -> Result<IpNet, ()> {
    if words.len() >= 2 {
        match (words[0].parse::<Ipv4Addr>(), words[1].parse::<Ipv4Addr>()) {
            (Ok(mask), Ok(ip)) => {
                let ipnet = Ipv4Net::new(ip, masklen(&mask)).unwrap();
                return Ok(ipnet.into());
            },
            _ => {},
        }
    }
    if !words[0].contains('/') {
        return match IpAddr::from_str(words[0]) {
            Ok(IpAddr::V4(ip)) => Ok(Ipv4Net::new(ip, 32).unwrap().into()),
            Ok(IpAddr::V6(ip)) => Ok(Ipv6Net::new(ip, 128).unwrap().into()),
            Err(_) => Err(()),
        };
    }
    IpNet::from_str(words[0]).map_err(|_| ())
}

/// Read a file in the NIS ypserv.securenets format.
pub fn read_securenets(file: impl AsRef<Path>, iplist: &mut IpList) -> io::Result<()> {
    let buffer = std::fs::read_to_string(&file)?;
    for line in buffer.split('\n') {
        let line = line.trim_left();
        if line.is_empty() || line.starts_with("#") {
            continue;
        }
        let words = line.split_whitespace().collect::<Vec<_>>();
        if let Ok(ipnet) = parse_ip(words) {
            iplist.add(ipnet);
        }
    }
    iplist.finalize();
    Ok(())
}
