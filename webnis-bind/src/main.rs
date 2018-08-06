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

mod config;
mod request;
mod response;

use std::fs;
use std::io;
use std::process::exit;
use std::time::{Duration,Instant};
use std::sync::{Arc,Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use futures::prelude::*;
use futures::stream;
use futures::sync::mpsc;
use tokio::prelude::*;
use tokio_uds::UnixListener;
use tokio_codec::Decoder;
use tk_listen::ListenExt;
use hyper::client::HttpConnector;
use hyper_tls::HttpsConnector;

use tokio_codec::LinesCodec;

// contains the currently active http client, and a sequence number.
pub struct HttpClient {
    client: Option<hyper::Client<HttpsConnector<HttpConnector>>>,
    seqno:  usize,
}

#[derive(Clone)]
pub struct Context {
    // config that we can clone
    config:         Arc<config::Config>,
    // a client that we can replace.
    http_client:    Arc<Mutex<HttpClient>>,
    // has client gone away?
    eof:            Arc<AtomicBool>,
    // priviliged?
    privileged:     bool,
}

const PROGNAME : &'static str = "webnis-bind";

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
            eprintln!("{}: {}", PROGNAME, e);
            exit(1);
        }
    };
    let http2_only = config.http2_only.unwrap_or(false);
    let mut concurrency = config.concurrency.unwrap_or(32);
    if http2_only && concurrency < 100 {
        concurrency = 100;
    }

    let seqno = std::process::id() as usize % (config.servers.len());
    let ctx = Context{
        config:         Arc::new(config),
		http_client:    Arc::new(Mutex::new(HttpClient{ client: None, seqno: seqno })),
        eof:            Arc::new(AtomicBool::new(false)),
        privileged:     false,
    };

    // Get a UNIX stream listener.
	let listener = match UnixListener::bind(&listen) {
        Ok(m) => Ok(m),
        Err(ref e) if e.kind() == io::ErrorKind::AddrInUse => {
            fs::remove_file(&listen).map_err(|e| {
                eprintln!("{}: {}: {}", PROGNAME, listen, e);
                exit(1);
            }).unwrap();
            UnixListener::bind(&listen)
        },
        Err(e) => Err(e),
    }.map_err(|e| {
        eprintln!("{}: {}: {}", PROGNAME, listen, e);
        exit(1);
    }).unwrap();
    println!("{}: listening on: {}", PROGNAME, listen);

    let server = listener.incoming()
        .map_err(|e| { eprintln!("{}: accept error = {:?}", PROGNAME, e); e })
        .sleep_on_error(Duration::from_millis(100))
        .map(move |socket| {

            // set up context for this session.
            let privileged = match socket.peer_cred() {
                Ok(creds) => creds.uid == 0 || creds.gid == 0,
                Err(_) => false,
            };
            let ctx = Context{
                config:         ctx.config.clone(),
                http_client:    ctx.http_client.clone(),
                eof:            Arc::new(AtomicBool::new(false)),
                privileged:     privileged,
            };

            // set up codec for reader and writer.
            let (writer, reader) = LinesCodec::new().framed(socket).split();

            // produce a final "EOF" error on the stream when the client has gone away.
            let final_eof = stream::once::<String, _>(Err(io::Error::new(io::ErrorKind::Other, "EOF")));
            let reader = reader.chain(final_eof);
            let eof_clone = ctx.eof.clone();

            // We read the incoming stream continously, and forward it onto a channel.
            // That way we can detect immediately if the client has gone away (EOF).
            let (tx, rx) = mpsc::channel(0);
            let fut = reader.then(move |res| {
                if let Err(_) = res {
                    //debug!("reader saw error, setting EOF flag in Context");
                    eof_clone.store(true, Ordering::SeqCst);
                }
                tx.clone().send(res)
            })
            .for_each(|_| Ok(()));

            // add a timeout. FIXME? this is a hard session timeout, not per-request.
            let timeout = Instant::now() + Duration::new(10, 0);
            let fut = fut.deadline(timeout).map_err(|e| {
                debug!("command reader timeout wrapper: error on {:?}", e);
                ()
            });
            tokio::spawn(fut);

            // The reader side of the channel reads Result<Result<Item, Error>, ()>.
            // Unwrap one level of Result.
            let reader = rx.then(|x| x.unwrap());

            // process commands and write result.
            let ctx = ctx.clone();
            let responses = reader.and_then(move |line| request::process(ctx.clone(), line));
            let session = writer.send_all(responses).map_err(|_| ()).map(|_| ());
            session
        })
        .listen(concurrency);

    tokio::run(server);
    exit(1);
}

