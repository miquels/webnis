use std::io;
use std::process::exit;

use openssl::ssl::{SslAcceptorBuilder, SslAcceptor, SslFiletype, SslMethod};

use super::PROGNAME;
use super::config::Config;

/// load ssl keys
pub fn acceptor(keyfile: &str, chainfile: &str) -> io::Result<SslAcceptorBuilder> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
		.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("opentls: {}", e)))?;
    builder
        .set_private_key_file(keyfile, SslFiletype::PEM)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}: {}", keyfile, e)))?;
    builder
		.set_certificate_chain_file(chainfile)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}: {}", keyfile, e)))?;
	Ok(builder)
}

/// load SSL keys and exit on fail.
pub fn acceptor_or_exit(config: &Config) -> SslAcceptorBuilder {
    let k = config.server.key_file.as_ref().unwrap();
    let c = config.server.crt_file.as_ref().unwrap();
    match acceptor(k, c) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}: {}", PROGNAME, e);
            exit(1);
        },
    }
}

