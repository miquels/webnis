
use std::io::prelude::*;
use std::io;
use std::fs::File;

use toml;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    #[serde(default)]
    pub domain:         String,
    pub password:       String,
    pub server:         Option<String>,
    #[serde(default)]
    pub servers:        Vec<String>,
    pub http2_only:     Option<bool>,
    pub concurrency:    Option<usize>,
    #[serde(default)]
    pub restrict_getpwuid:  bool,
    #[serde(default)]
    pub restrict_getgrgid:  bool,
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
    if config.domain.as_str() == "" {
        config.domain = "default".to_string();
    }

    Ok(config)
}
