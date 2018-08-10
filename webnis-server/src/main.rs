#[macro_use] extern crate clap;
#[macro_use] extern crate log;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
extern crate actix;
extern crate actix_web;
extern crate base64;
extern crate env_logger;
extern crate futures;
extern crate gdbm;
extern crate http;
extern crate libc;
extern crate net2;
extern crate openssl;
extern crate percent_encoding;
extern crate pwhash;
extern crate serde;
extern crate toml;

pub(crate) mod config;
pub(crate) mod db;
pub(crate) mod format;
pub(crate) mod ssl;
pub(crate) mod util;
pub(crate) mod webnis;

use std::net::{SocketAddr,ToSocketAddrs};
use std::process::exit;

use actix_web::{
    server, pred,
    App, AsyncResponder,
    HttpRequest, HttpResponse, HttpMessage,
    FromRequest, Path,
    http::StatusCode,
};
use futures::{future,Future};

use util::*;

use webnis::Webnis;

static PROGNAME: &'static str = "webnis-server";


fn main() {

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

    let webnis = Webnis::new(config.clone());

    let sys = actix::System::new("webnis");

    let ct = "content-type";
    let x_www_form = "application/x-www-form-urlencoded";
    let app_factory = move |prefix, webnis| {
            App::with_state(webnis)
                .prefix(prefix)
                .resource("/{domain}/auth", move |r| {
                    r.method(http::Method::POST)
                        .filter(pred::Header(ct, x_www_form))
                        .f(handle_auth);
                    r.method(http::Method::POST)
                        .filter(pred::Not(pred::Header(ct, x_www_form)))
                        .f(|_| HttpResponse::UnsupportedMediaType());
                    r.route()
                        .filter(pred::Not(pred::Post()))
                        .f(|_| HttpResponse::MethodNotAllowed());
                })
                .resource("/{domain}/map/{map}", |r| {
                    r.method(http::Method::GET).f(handle_map);
                    r.route()
                        .filter(pred::Not(pred::Get()))
                        .f(|_| HttpResponse::MethodNotAllowed());
                })
    };

    let mut server = server::new(move || {
        let webnis = webnis.clone();
        vec![
            app_factory("/webnis", webnis.clone()),
            app_factory("/.well-known/webnis", webnis.clone()),
            App::with_state(webnis).resource("/", |r| r.f(|_| HttpResponse::NotFound())),
        ]
    });

	for sockaddr in config.server.listen.to_socket_addrs().unwrap() {
        let listener = match make_listener(&sockaddr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{}: listener on {}: {}", PROGNAME, &sockaddr, e);
                exit(1);
            },
        };
        let result = if config.server.tls {
            server.listen_ssl(listener, ssl::acceptor_or_exit(&config))
        } else {
            Ok(server.listen(listener))
        };
        server = match result {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{}: listener on {:?}: {}", PROGNAME, &sockaddr, e);
                exit(1);
            },
        };
        let proto = if config.server.tls { "https" } else { "http" };
        println!("Listening on {}://{:?}", proto, sockaddr);
    }
    server.start();

    let _ = sys.run();
}

fn check_authorization(req: &HttpRequest<Webnis>, domain: &str) -> Option<HttpResponse> {
    let passwd = match req.state().domain_password(domain) {
        None => return None,
        Some(p) => p,
    };
    match check_basic_auth(req.headers(), None, Some(passwd)) {
        AuthResult::NoAuth => Some(http_unauthorized()),
        AuthResult::BadAuth => Some(http_error(StatusCode::FORBIDDEN, "Bad credentials")),
        AuthResult::AuthOk => None,
    }
}

fn handle_map(req: &HttpRequest<Webnis>) -> HttpResponse {
    let params = match Path::<(String, String)>::extract(req) {
        Err(_) => return HttpResponse::InternalServerError().body("handle_map should not fail\n"),
        Ok(d) => d,
    };
    if let Some(denied) = check_authorization(req, &params.0) {
        return denied;
    }
    req.state().handle_map(&params.0, &params.1, &req.query())
}

fn handle_auth(req: &HttpRequest<Webnis>) -> Box<Future<Item=HttpResponse, Error=actix_web::Error>> {
    let domain = match Path::<String>::extract(req) {
        Err(_) => return Box::new(future::ok(HttpResponse::InternalServerError().body("handle_auth should not fail\n"))),
        Ok(d) => d,
    };
    if let Some(denied) = check_authorization(req, &domain) {
        return Box::new(future::ok(denied));
    }
    let webnis = req.state().clone();
    let domain = domain.clone();
    req.body()
        .limit(1024)
        .from_err()
        .and_then(move |data| {
            future::ok(webnis.handle_auth(domain, data.to_vec()).into())
        })
        .responder()
}

// Make a new TcpListener, and if it's a V6 listener, set the
// V6_V6ONLY socket option on it.
fn make_listener(addr: &SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let s = if addr.is_ipv6() {
        let s = net2::TcpBuilder::new_v6()?;
        s.only_v6(true)?;
        s
    } else {
        net2::TcpBuilder::new_v4()?
    };
    s.bind(addr)?;
    s.listen(128)
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

