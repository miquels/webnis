#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;

pub(crate) mod datalog;
#[macro_use]
pub(crate) mod errors;
pub(crate) mod config;
pub(crate) mod db;
pub(crate) mod format;
pub(crate) mod iplist;
pub(crate) mod lua;
pub(crate) mod ssl;
pub(crate) mod util;
pub(crate) mod webnis;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::process::exit;
use std::str::FromStr;

use actix;
use actix_web;
use env_logger;
use failure;
use futures;
use http;
use libc;
use net2;

use actix_web::{
    http::StatusCode, pred, server, App, AsyncResponder, FromRequest, HttpMessage, HttpRequest, HttpResponse,
    Path,
};
use futures::{future, Future};

use crate::iplist::IpList;
use crate::util::*;
use crate::webnis::Webnis;

static PROGNAME: &'static str = "webnis-server";

const CT: &'static str = "content-type";
const X_WWW_FORM: &'static str = "application/x-www-form-urlencoded";
const APPL_JSON: &'static str = "application/json";

fn main() {
    env_logger::init();

    let matches = clap_app!(webnis_server =>
        (version: "0.3")
        (@arg CFG: -c --config +takes_value "configuration file (/etc/webnis-server.toml)")
        (@arg SYN: -x --syntaxcheck "syntax check configuration files")
    )
    .get_matches();
    let cfg = matches.value_of("CFG").unwrap_or("/etc/webnis-server.toml");
    let syntax = matches.is_present("SYN");

    let config = match config::read(cfg) {
        Err(e) => {
            eprintln!("{}: {}: {}", PROGNAME, cfg, e);
            exit(1);
        },
        Ok(c) => c,
    };
    if config.domain.len() == 0 {
        eprintln!("{}: no domains defined in {}", PROGNAME, cfg);
        exit(1);
    }

    // read /etc/ypserv.securenets if configured.
    let securenets = if config.server.securenets_.len() > 0 {
        let mut iplist = IpList::new();
        for file in &config.server.securenets_ {
            if let Err(e) = config::read_securenets(file, &mut iplist) {
                eprintln!("{}: {:?}: {}", PROGNAME, file, e);
                exit(1);
            }
        }
        Some(iplist)
    } else {
        None
    };

    // arbitrary limit, really.
    raise_rlimit_nofile(64000);

    // initialize webnis stuff
    let webnis = Webnis::new(config.clone(), securenets);

    // initialize datalog stuff.
    let _datalog_guard = match config.server.datalog {
        Some(ref datalog) => {
            match datalog::init(datalog) {
                Ok(g) => Some(g),
                Err(e) => {
                    eprintln!("{}: {}: {}", PROGNAME, datalog, e);
                    exit(1);
                }
            }
        },
        None => None,
    };

    // initialize lua stuff
    if let Some(ref l) = config.lua {
        if let Err(e) = lua::lua_init(&l.script_) {
            eprintln!("{}: {:?} {}", PROGNAME, l.script_, e);
            exit(1);
        }
    }

    if syntax {
        println!("configuration parsed succesfully");
        return;
    }

    let sys = actix::System::new("webnis");

    let app_factory = move |prefix, webnis| {
        App::with_state(webnis)
            .prefix(prefix)
            .resource("/{domain}/map/{map}", |r| {
                r.method(http::Method::GET).f(handle_map);
                r.route()
                    .filter(pred::Not(pred::Get()))
                    .f(|_| HttpResponse::MethodNotAllowed());
            })
            .resource("/{domain}/auth", move |r| {
                r.method(http::Method::POST)
                    .filter(pred::Any(pred::Header(CT, X_WWW_FORM)).or(pred::Header(CT, APPL_JSON)))
                    .f(handle_auth);
                r.method(http::Method::POST)
                    .filter(pred::Not(
                        pred::Any(pred::Header(CT, X_WWW_FORM)).or(pred::Header(CT, APPL_JSON)),
                    ))
                    .f(|_| HttpResponse::UnsupportedMediaType());
                r.route()
                    .filter(pred::Not(pred::Post()))
                    .f(|_| HttpResponse::MethodNotAllowed());
            })
            .resource("/{domain}/info", |r| {
                r.method(http::Method::GET).f(handle_info);
                r.route()
                    .filter(pred::Not(pred::Get()))
                    .f(|_| HttpResponse::MethodNotAllowed());
            })
    };

    let mut server = server::new(move || {
        let webnis = webnis.clone();
		db::Timer::start_timer();
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
        eprintln!("Listening on {}://{:?}", proto, sockaddr);
    }
    server.start();

    let _ = sys.run();
}

// Authorize the request.
//
// - get client IP address, fatal if we fail.
// - check against the "securenets" file if needed
// - check HTTP authentication
// - on success,return client IP address.
//
fn check_authorization(req: &HttpRequest<Webnis>, domain: &str) -> Result<IpAddr, HttpResponse> {
    let webnis = req.state();

    let pa = match req.peer_addr() {
        Some(ip) => ip,
        None => {
            warn!("check_authorization: request has no source IP address?!");
            return Err(http_error(StatusCode::INTERNAL_SERVER_ERROR, "Can't get client IP"));
        },
    };

    let mut ip = pa.ip();
    trace!("peer ip is {}", ip);
    if ip.is_loopback() {
        trace!("peer ip is loopback");
        if let Some(remote) = req.connection_info().remote() {
            trace!("connectioninfo remote is {}", remote);
            if let Ok(ipaddr) = IpAddr::from_str(remote) {
                ip = ipaddr;
            }
        }
    }

    // check the securenets access list.
    if let Some(ref sn) = webnis.inner.securenets {
        trace!("checking securenets");
        if !sn.contains(ip) && !ip.is_loopback() {
            warn!("securenets: access denied for peer {}", ip);
            return Err(http_error(StatusCode::FORBIDDEN, "Access denied"));
        }
    }

    // check HTTP authentication.
    let domdef = match webnis.inner.config.find_domain(domain) {
        None => return Err(http_error(StatusCode::NOT_FOUND, "Not found")),
        Some(d) => d,
    };
    match check_http_auth(req.headers(), domdef) {
        AuthResult::NoAuth | AuthResult::BadAuth => {
            Err(http_unauthorized(&domdef.name, domdef.http_authschema.as_ref()))
        },
        AuthResult::AuthOk => Ok(ip),
    }
}

fn handle_map(req: &HttpRequest<Webnis>) -> HttpResponse {
    let params = match Path::<(String, String)>::extract(req) {
        Err(_) => return HttpResponse::InternalServerError().body("handle_map should not fail\n"),
        Ok(d) => d,
    };
    if let Err(denied) = check_authorization(req, &params.0) {
        return denied;
    }
    let keyname = req.query_string().split('=').next();
    debug!("handle_map: [{}] [{}] [{:?}]", params.0, params.1, req.query());
    req.state().handle_map(&params.0, &params.1, keyname, &req.query())
}

fn handle_info(req: &HttpRequest<Webnis>) -> HttpResponse {
    let domain = match Path::<String>::extract(req) {
        Err(_) => return HttpResponse::InternalServerError().body("handle_info should not fail\n"),
        Ok(d) => d,
    };
    if let Err(denied) = check_authorization(req, &domain) {
        return denied;
    }
    req.state().handle_info(&domain)
}

fn handle_auth(req: &HttpRequest<Webnis>) -> Box<dyn Future<Item = HttpResponse, Error = actix_web::Error>> {
    let domain = match Path::<String>::extract(req) {
        Err(_) => {
            return Box::new(future::ok(
                HttpResponse::InternalServerError().body("handle_auth should not fail\n"),
            ));
        },
        Ok(d) => d,
    };
    let ip = match check_authorization(req, &domain) {
        Ok(ip) => ip,
        Err(denied) => return Box::new(future::ok(denied)),
    };

    let is_json = match req.request().headers().get("content-type").map(|v| v.to_str().ok()).flatten() {
        Some(ct) => {
            let ct = ct.split(';').next().unwrap().trim();
            ct == "application/json" || ct == "text/json"
        },
        None => false,
    };

    let webnis = req.state().clone();
    let domain = domain.clone();
    req.body()
        .limit(4096)
        .from_err()
        .and_then(move |data| future::ok(webnis.handle_auth(domain, ip, is_json, data.to_vec()).into()))
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
    s.reuse_address(true).ok();
    s.bind(addr)?;
    s.listen(128)
}

fn raise_rlimit_nofile(want_lim: libc::rlim_t) {
    // get current rlimit.
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
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
        let new_rlim = libc::rlimit {
            rlim_cur: lim,
            rlim_max: rlim.rlim_max,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new_rlim as *const libc::rlimit) } != 0 {
            return;
        }
        if lim >= want_lim {
            return;
        }
    }

    // still not enough? try upping the hard limit.
    let new_rlim = libc::rlimit {
        rlim_cur: want_lim,
        rlim_max: want_lim,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new_rlim as *const libc::rlimit) };
}
