#[macro_use] extern crate serde_derive;
#[macro_use] extern crate clap;
#[macro_use] extern crate log;
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
extern crate tk_listen;

mod cmd;
mod config;
mod codec;
mod response;

use std::fs;
use std::io;
use std::process::exit;
use std::sync::{Arc,Mutex};
use std::time::Duration;

use futures::prelude::*;
use tokio_uds::UnixListener;
use tokio_codec::Decoder;
use tk_listen::ListenExt;
use hyper::client::HttpConnector;
use hyper_tls::HttpsConnector;

use codec::LinesCodec;

#[derive(Clone)]
//#[derive(Debug,Clone)]
pub struct Context {
    // config that we can clone
    config:      Arc<config::Config>,
    // a client that we can replace.
    client:     Arc<Mutex<Option<hyper::Client<HttpsConnector<HttpConnector>>>>>,
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
    let http2_only = config.http2_only.unwrap_or(false);
    let mut concurrency = config.concurrency.unwrap_or(32);
    if http2_only && concurrency < 100 {
        concurrency = 100;
    }

    let ctx = Context{
        config: Arc::new(config),
		client: Arc::new(Mutex::new(None)),
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

    let server = listener.incoming()
        .map_err(|e| { eprintln!("accept error = {:?}", e); e })
        .sleep_on_error(Duration::from_millis(100))
        //.map_err(|_| ())
        .map(move |socket| {
            let (writer, reader) = LinesCodec::new(ctx.clone()).framed(socket).split();
            let responses = reader.and_then(|(ctx, line)| cmd::process(ctx, line));
            let session = writer.send_all(responses).map_err(|_| ()).map(|_| ());
            session.map_err(|_| ())
        })
        // .listen(concurrency) from tk-listen is the same as this:
        //.buffer_unordered(concurrency).for_each(|()| Ok(()));
        .listen(concurrency);

    tokio::run(server);
    exit(1);
}

