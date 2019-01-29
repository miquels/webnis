use std::io;
use std::process::exit;

use openssl::ssl;
use openssl::ssl::{
    SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod, SslOptions, SslSessionCacheMode,
};

use crate::config::Config;
use crate::PROGNAME;

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
    builder.set_verify(ssl::SslVerifyMode::NONE);

    let mut options = ssl::SslOptions::empty();
    options.insert(SslOptions::NO_COMPRESSION);
    options.insert(SslOptions::CIPHER_SERVER_PREFERENCE);
    options.insert(SslOptions::NO_SSLV2);
    options.insert(SslOptions::NO_SSLV3);
    options.insert(SslOptions::NO_TLSV1);
    options.insert(SslOptions::NO_TLSV1_1);
    builder.set_options(options);

    let mode = SslSessionCacheMode::SERVER;
    builder.set_session_cache_mode(mode);

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
