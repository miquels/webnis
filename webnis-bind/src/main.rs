#[macro_use] extern crate serde_derive;
#[macro_use] extern crate clap;
extern crate bytes;
extern crate serde;
extern crate serde_json;
extern crate futures;
extern crate tokio;
extern crate tokio_uds;
extern crate tokio_codec;
extern crate hyper;
extern crate hyper_tls;
extern crate url;
extern crate env_logger;
extern crate toml;
extern crate libc;

mod cmd;
mod config;
mod codec;
mod response;

use std::fs;
use std::io;
use std::process::exit;
use std::sync::Arc;

use futures::prelude::*;
use tokio_uds::UnixListener;
use tokio_codec::Decoder;

use codec::LinesCodec;

#[derive(Debug,Clone)]
pub struct Context {
    inner:      Arc<InnerContext>,
}

#[derive(Debug,Clone)]
pub struct InnerContext {
    config:     config::Config,
}

fn main() {
    env_logger::init().unwrap();

    let matches = clap_app!(webnis_bind =>
        (version: "0.1")
        (@arg LISTEN: -l --listen +takes_value "unix domain socket to listen on (/var/run/webnis-bind.sock)")
        (@arg CFG: -c --config +takes_value "configuration file (/etc/webnis-bind.toml)")
    ).get_matches();

    let listen = matches.value_of("LISTEN").unwrap_or("/var/run/webnis-bind.sock");
    let cfg = matches.value_of("CFG").unwrap_or("/etc/webnis-bind.toml");

    let config = match config::read(cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    };
    let ctx = Context{
        inner: Arc::new(InnerContext{
            config: config,
        }),
    };

	let listener = match UnixListener::bind(&listen) {
        Ok(m) => Ok(m),
        Err(ref e) if e.kind() == io::ErrorKind::AddrInUse => {
            fs::remove_file(&listen).unwrap();
            UnixListener::bind(&listen)
        },
        Err(e) => Err(e),
    }.expect("failed to bind");
    println!("Listening on: {}", listen);

    let conns = listener.incoming().map_err(|e| eprintln!("error = {:?}", e));
    let server = conns.for_each(move |socket| {
        let (writer, reader) = LinesCodec::new(ctx.clone()).framed(socket).split();
        let responses = reader.and_then(|(ctx, line)| cmd::process(ctx, line));
        let session = writer.send_all(responses).map_err(|_| ()).map(|_| ());
        tokio::spawn(session);
        Ok(())
    })
    .map_err(|err| {
        eprintln!("server error {:?}", err);
    });

    tokio::run(server);
    exit(1);
}

