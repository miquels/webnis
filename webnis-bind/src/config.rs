
use std::io::prelude::*;
use std::io;
use std::fs::File;

use toml;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub domain:     Option<String>,
    pub password:   String,
    pub server:     Option<String>,
    #[serde(default)]
    pub servers:    Vec<String>,
}

pub fn read(name: &str) -> io::Result<Config> {
    let mut f = File::open(name)?;
    let mut buffer = String::new();
    f.read_to_string(&mut buffer)?;

    let mut config : Config = match toml::from_str(&buffer) {
        Ok(v) => Ok(v),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: {}", name, e))),
    }?;

    if let Some(s) = config.server.take() {
        config.servers.push(s);
    }
    if config.servers.len() == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no servers defined"));
    }
    Ok(config)
}
