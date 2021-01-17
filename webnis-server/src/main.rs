#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::iter::FromIterator;
use std::net::{IpAddr, SocketAddr};
use std::panic;

use futures::stream::FuturesUnordered;
use http::StatusCode;
use structopt::StructOpt;
use tokio::stream::StreamExt;
use tokio::task;
use warp::Filter;

pub(crate) mod datalog;
#[macro_use]
pub(crate) mod errors;
pub(crate) mod config;
pub(crate) mod db;
pub(crate) mod format;
pub(crate) mod iplist;
pub(crate) mod lua;
pub(crate) mod remoteip;
pub(crate) mod util;
pub(crate) mod webnis;

use crate::iplist::IpList;
use crate::util::*;
use crate::webnis::Webnis;

static PROGNAME: &'static str = "webnis-server";

const X_WWW_FORM: &'static str = "application/x-www-form-urlencoded";
const APPL_JSON: &'static str = "application/json";
const TEXT_JSON: &'static str = "text/json";

macro_rules! die {
    (log => $($tt:tt)*) => ({
        log::error!($($tt)*);
        std::process::exit(1);
    });
    (std => $($tt:tt)*) => ({
        eprintln!($($tt)*);
        std::process::exit(1);
    });
}

#[derive(Debug, StructOpt)]
struct Opts {
    /// configuration file (/etc/webnis-server.toml)
    #[structopt(default_value = "/etc/webnis-server.toml")]
    cfg:    String,

    /// syntax check configuration files
    #[structopt(short = "x", long = "syntaxcheck")]
    syntax: bool,
}

async fn async_main() {
    let opts = Opts::from_args();

    let config = match config::read(&opts.cfg) {
        Err(e) => die!(std => "{}: {}: {}", PROGNAME, opts.cfg, e),
        Ok(c) => c,
    };
    if config.domain.len() == 0 {
        die!(std => "{}: no domains defined in {}", PROGNAME, opts.cfg);
    }

    // read /etc/ypserv.securenets if configured.
    let securenets = if config.server.securenets_.len() > 0 {
        let mut iplist = IpList::new();
        for file in &config.server.securenets_ {
            if let Err(e) = config::read_securenets(file, &mut iplist) {
                die!(std => "{}: {:?}: {}", PROGNAME, file, e);
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
            match datalog::init(datalog).await {
                Ok(g) => Some(g),
                Err(e) => die!(std => "{}: {}: {}", PROGNAME, datalog, e),
            }
        },
        None => None,
    };

    // initialize lua stuff
    if let Some(ref l) = config.lua {
        if let Err(e) = lua::lua_init(&l.script_) {
            die!(std => "{}: {:?} {}", PROGNAME, l.script_, e);
        }
    }

    if opts.syntax {
        println!("configuration parsed succesfully");
        return;
    }

    // All the API handlers get /{domain}/ passed by default.

    // /{domain}/map/{map}
    let map = check_authorization(&webnis, "map")
        .and(warp::path::param())
        .and(warp::query::raw())
        .and(warp::path::end())
        .and(warp::filters::method::get())
        .and_then(move |webnis: Webnis, domain: String, _ip: IpAddr, map: String, query: String| async move {
            let keyname = if query == "" {
                None
            } else {
                query.split('=').next()
            };
            let query = query.split('&').into_iter().map(|param| {
                let mut kv = param.splitn(2, '=');
                (kv.next().unwrap().to_string(), kv.next().unwrap_or("").to_string())
            });
            let query = HashMap::from_iter(query);
            debug!("handle_map: [{}] [{}] [{:?}]", domain, map, query);
            webnis.handle_map(&domain, &map, keyname, &query)
        });

    // /{domain}/{auth}
    let auth = check_authorization(&webnis, "auth")
        .and(warp::path::end())
        .and(warp::filters::method::post())
        .and(warp::header("content-type"))
        .and(warp::body::bytes())
        .and_then(move |webnis: Webnis, domain: String, ip: IpAddr, ct: String, body: bytes::Bytes| async move {
            let ct = ct.split(';').next().unwrap().trim();
            if ct != X_WWW_FORM && ct != APPL_JSON && ct != TEXT_JSON {
                return Err(Reject::status(StatusCode::METHOD_NOT_ALLOWED, "only POST allowed"));
            }
            let is_json = ct != X_WWW_FORM;
            webnis.handle_auth(domain, ip, is_json, body.to_vec())
        });

    // /{domain}/{info}
    let info = check_authorization(&webnis, "info")
        .and(warp::path::end())
        .and(warp::filters::method::get())
        .and_then(move |webnis: Webnis, domain: String, _: IpAddr| async move {
            webnis.handle_info(&domain)
        });

    let api = map.or(auth).or(info);
    let routes = warp::path("/webnis").or(warp::path("/.well-known/webnis")).unify().and(api);
    let routes = routes.recover(Reject::handle_rejection);

    let mut handles = Vec::new();
    for (addr, name) in &config.server.listen {
        if config.server.tls {
            // why no try_bind_ephemeral in the TlsServer?
            let srv = warp::serve(routes.clone());
            let srv = srv
                .tls()
                .key_path(config.server.key_file.as_ref().unwrap())
                .cert_path(config.server.crt_file.as_ref().unwrap())
                .bind(addr);
            log::info!("Listening on {}", name);
            handles.push(task::spawn(srv));
        } else {
            match warp::serve(routes.clone()).try_bind_ephemeral(addr) {
                Ok((_, srv)) => {
                    log::info!("Listening on {}", name);
                    handles.push(task::spawn(srv));
                }
                Err(e) => die!(log => "{}: {}", name, e),
            }
        }
    }

    // start db housekeeping task.
    db::Timer::start_timer().await;

    // The tasks should never return, only on error. So _if_ one
    // returns, abort the entire process.
    let mut task_waiter = FuturesUnordered::new();
    for handle in handles.drain(..) {
        task_waiter.push(handle);
    }
    if let Some(Err(err)) = task_waiter.next().await {
        if let Ok(cause) = err.try_into_panic() {
            if let Some(err) = cause.downcast_ref::<String>() {
                die!(log => "fatal: {}", err);
            }
        }
    }
    die!(log => "server exited unexpectedly");
}

fn main() {
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::init_from_env(env);

    let mut rt = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .on_thread_start(|| {
            let hook = panic::take_hook();
            panic::set_hook(Box::new(move |info| {
                match info.payload().downcast_ref::<String>() {
                    Some(msg) if msg.contains("error binding to") => {}
                    _ => hook(info),
                }
            }));
        })
        .build()
        .unwrap();
    rt.block_on(async_main());
}

// Authorize the request.
//
// - get client IP address, fatal if we fail.
// - check against the "securenets" file if needed
// - check HTTP authentication
// - on success,return client IP address.
//
fn check_authorization(
    webnis: &Webnis,
    pathelem: &'static str,
) -> impl Filter<Extract = (Webnis, String, IpAddr,), Error = warp::reject::Rejection> + Clone {
    let webnis_ = webnis.clone();

    warp::any()
        .map(move || webnis_.clone())
        .and(warp::path::param())
        .and(warp::path(pathelem))
        .and(remoteip::remoteip(false))
        .and(warp::header::optional("authorization"))
        .and_then(|webnis: Webnis, domain: String, sa: Option<SocketAddr>, authz: Option<String>| async move {

            let ip = sa
                .map(|sa| sa.ip())
                .ok_or_else(|| Reject::status(StatusCode::BAD_REQUEST, "no client ip addr"))?;

            // check the securenets access list.
            if let Some(ref sn) = webnis.inner.securenets {
                trace!("checking securenets");
                if !sn.contains(ip) && !ip.is_loopback() {
                    warn!("securenets: access denied for peer {}", ip);
                    return Err(Reject::status(StatusCode::FORBIDDEN, "access denied"));
                }
            }

            // check HTTP authentication.
            let domdef = match webnis.inner.config.find_domain(&domain) {
                None => return Err(warp::reject::not_found()),
                Some(d) => d,
            };
            match check_http_auth(authz, domdef) {
                AuthResult::NoAuth | AuthResult::BadAuth => {
                    Err(http_unauthorized(&domdef.name, domdef.http_authschema.as_ref()))
                },
                AuthResult::AuthOk => Ok((webnis, domain, ip)),
            }
        })
        .untuple_one()
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
