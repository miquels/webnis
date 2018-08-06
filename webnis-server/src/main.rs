#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate log;
#[macro_use] extern crate clap;
extern crate serde;
extern crate hyper;
extern crate env_logger;
extern crate toml;
extern crate futures;
extern crate gdbm;
extern crate http;
extern crate libc;
extern crate pwhash;
extern crate routematcher;
extern crate hyper_tls_hack;
extern crate openssl;
extern crate native_tls;

pub(crate) mod config;
pub(crate) mod db;
pub(crate) mod format;
pub(crate) mod webnis;
pub(crate) mod util;

use std::net::ToSocketAddrs;
use std::process::exit;

use futures::future::{self, Either};
use futures::Stream;
use hyper::rt::{self, Future};
use hyper::{Body, Request, Response, Server, StatusCode, header};
use hyper::service::{Service,NewService};
use http::Method;

use routematcher::Builder;
use util::*;

use webnis::Webnis;

static PROGNAME: &'static str = "webnis-server";

fn main() -> Result<(), Box<std::error::Error>> {

    env_logger::init();

    let matches = clap_app!(webnis_server =>
        (version: "0.1")
        (@arg CFG: -c --config +takes_value "configuration file (/etc/webnis-server.toml)")
    ).get_matches();
    let cfg = matches.value_of("CFG").unwrap_or("/etc/webnis-server.toml");

    let config = match config::read(cfg) {
        Err(e) => {
            eprintln!("{}: {}: {}", PROGNAME, cfg, e);
            exit(1);
        }
        Ok(c) => c,
    };
    if config.domain.len() == 0 {
        eprintln!("{}: no domains defined in {}", PROGNAME, cfg);
        exit(1);
    }

    // arbitrary limit, really.
    raise_rlimit_nofile(64000);

    // build the routes we're going to serve.
    let builder = Builder::new();
    builder
        .add("/webnis/:domain/map/:map")
        .method(&Method::GET)
        .label("map");
    builder
        .add("/.well-known/webnis/:domain/map/:map")
        .method(&Method::GET)
        .label("map");
    builder
        .add("/webnis/:domain/auth")
        .method(&Method::POST)
        .label("auth");
    builder
        .add("/.well-known/webnis/:domain/auth")
        .method(&Method::POST)
        .label("auth");
    let matcher = builder.compile();
    let webnis = Webnis::new(matcher, config.clone());

    let tls_acceptor = if config.server.tls {
        let tls_acceptor = if config.server.p12_file.is_some() {
            hyper_tls_hack::acceptor_from_file(config.server.p12_file.unwrap(),
                                               &config.server.cert_password)
        } else {
            acceptor_from_pem_files(config.server.key_file.unwrap(),
                                    config.server.crt_file.unwrap(),
                                    &config.server.cert_password)
        };
        match tls_acceptor {
            Err(e) => {
                eprintln!("{}: {}", PROGNAME, e);
                exit(1);
            },
            Ok(a) => Some(a),
        }
    } else {
        None
    };

    // start the servers.
    let mut servers = Vec::new();
    for sockaddr in config.server.listen.to_socket_addrs().unwrap() {
        let proto = if config.server.tls { "https" } else { "http" };
        println!("Listening on {}://{:?}", proto, sockaddr);
        let server = if config.server.tls {
            let acceptor = tls_acceptor.as_ref().unwrap().clone();
            let mut ai = match hyper_tls_hack::AddrIncoming::new(&sockaddr, acceptor, None) {
                Err(e) => {
                    eprintln!("{}: tlslistener on {:?}: {}", PROGNAME, &sockaddr, e);
                    exit(1);
                },
                Ok(ai) => ai,
            };
            ai.set_nodelay(true);
            Either::A(
                Server::builder(ai)
                    .serve(webnis.clone())
                    .map_err(|e| eprintln!("https server error: {}", e))
            )
        } else {
            Either::B(
                match Server::try_bind(&sockaddr) {
                    Err(e) => {
                        eprintln!("{}: listener on {:?}: {}", PROGNAME, &sockaddr, e);
                        exit(1);
                    },
                    Ok(s) => s,
                }
                .tcp_nodelay(true)
                .serve(webnis.clone())
                .map_err(|e| eprintln!("http server error: {}", e))
            )
        };
        servers.push(server);
    }

    // wait for all servers to finish.
    let fut = future::join_all(servers).then(|_| Ok(()));
    rt::run(fut);

    Ok(())
}

// new_service() gets called by hyper every time a new HTTP connection
// is made. It returns a "Service" which is called for every HTTP
// request on this connection.
//
// Often this trait is implemented on a seperate struct from the
// main service, but there is no reason why a struct cannot implement
// both the NewService and Service traits.
impl NewService for Webnis {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = BoxedError;
	type Service = Self;
	type Future = future::FutureResult<Self::Service, Self::InitError>;
    type InitError = BoxedError;

    fn new_service(&self) -> <Self as NewService>::Future {
        future::ok(self.clone())
    }
}

// This is the actual HTTP request handler.
impl Service for Webnis {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = BoxedError;
    type Future = BoxedFuture;

    fn call(&mut self, mut req: Request<<Self as Service>::ReqBody>) -> BoxedFuture {
        debug!("{}", req.uri());

        // Route matcher preflight.
        if let Err(resp) = self.inner.matcher.preflight_resp(&mut req) {
            return Box::new(future::ok(resp));
        }

        match req.method() {
            &Method::GET => {
                self.serve(req)
            },
            &Method::POST => {
                // first some claning and moving around of values to keep
                // the borrow checker happy.
                let (parts, body) = req.into_parts();
                let mut req = Request::from_parts(parts, Body::empty());
                let mut self2 = self.clone();
                // Then read the body, decode it, and call self.serve()
                let future = body
                    .concat2()
                    .map_err(box_error)
                    .then(move |res| {
                        match res.and_then(|b| {
                                self2.inner.matcher.parse_body(&mut req, &b).map_err(box_error)
                            }) {
                            Ok(()) => self2.serve(req),
                            Err(_) => {
                                Box::new(future::ok(Response::builder()
                                    .header(header::CONTENT_TYPE, "text/plain")
                                    .header(header::CONNECTION, "close")
                                    .status(StatusCode::BAD_REQUEST)
                                    .body("Failed to read/parse body\n".into()).unwrap()))
                            }
                        }
                    });
                Box::new(future)
            },
            _ => {
                http_error(StatusCode::INTERNAL_SERVER_ERROR, "This did not happen (or did it?)")
            },
        }
    }
}

fn raise_rlimit_nofile(want_lim: libc::rlim_t) {
    // get current rlimit.
    let mut rlim = libc::rlimit{ rlim_cur: 0, rlim_max: 0 };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim as *mut libc::rlimit) } != 0 {
        return;
    }

    // might be enough already.
    if rlim.rlim_cur >= want_lim {
        return;
    }

    // if the current soft limit is smaller than the current hard limit,
    // first try raising the soft limit as far as we can or need.
    if rlim.rlim_cur < rlim.rlim_max {
        let lim = std::cmp::min(want_lim, rlim.rlim_max);
        let new_rlim = libc::rlimit{ rlim_cur: lim, rlim_max: rlim.rlim_max };
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new_rlim as *const libc::rlimit) } != 0 {
                return
        }
        if lim >= want_lim {
            return;
        }
    }

    // still not enough? try upping the hard limit.
    let new_rlim = libc::rlimit{ rlim_cur: want_lim, rlim_max: want_lim };
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new_rlim as *const libc::rlimit) };
}

