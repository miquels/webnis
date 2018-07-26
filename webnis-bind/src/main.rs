#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate futures;
extern crate tokio;
extern crate tokio_uds;
extern crate tokio_codec;
extern crate hyper;
extern crate hyper_tls;
extern crate url;

mod cmd;

use std::env;
use std::fs;
use std::io;

use futures::prelude::*;
use tokio::prelude::*;
use tokio_uds::UnixListener;
use tokio_codec::LinesCodec;
use tokio_codec::Decoder;

fn main() {
    let addr = env::args().nth(1).unwrap_or("webnis-bind.sock".to_string());
	let listener = match UnixListener::bind(&addr) {
        Ok(m) => Ok(m),
        Err(ref e) if e.kind() == io::ErrorKind::AddrInUse => {
            fs::remove_file(&addr).unwrap();
            UnixListener::bind(&addr)
        },
        Err(e) => Err(e),
    }.expect("failed to bind");
    println!("Listening on: {}", addr);

    let conns = listener.incoming().map_err(|e| println!("error = {:?}", e));
    let server = conns.for_each(move |socket| {
        let (writer, reader) = LinesCodec::new().framed(socket).split();
        let responses = reader.and_then(cmd::process);
        let session = writer.send_all(responses).map_err(|_| ()).map(|_| ());
        tokio::spawn(session);
        Ok(())
    })
    .map_err(|err| {
        println!("server error {:?}", err);
    });

    tokio::run(server);
}

