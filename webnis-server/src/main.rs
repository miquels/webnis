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

mod config;
mod db;
mod format;

use std::net::ToSocketAddrs;
use std::process::exit;
use std::sync::Arc;

use futures::future::{self, Either};
use hyper::rt::{self, Future};
use hyper::{Body, Request, Response, Server, StatusCode, header};
use hyper::service::{Service,NewService};
use http::Method;

use routematcher::{Builder,Matcher,Match};
use db::DbError;

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
        .method(&Method::GET)
        .method(&Method::POST)
        .label("auth");
    builder
        .add("/.well-known/webnis/:domain/auth")
        .method(&Method::GET)
        .method(&Method::POST)
        .label("auth");
    let matcher = builder.compile();
    let webnis = Webnis::new(matcher, config.clone());

    let tls_acceptor = if config.server.tls {
        let f = match config.server.cert_file {
            None => {
                eprintln!("{}: [server] tls enabled, but cert_file not set", PROGNAME);
                exit(1);
            },
            Some(ref f) => f,
        };
        match hyper_tls_hack::acceptor_from_file(f, &config.server.cert_password) {
            Err(e) => {
                eprintln!("{}: {}: {}", PROGNAME, f, e);
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

// helpers.
fn http_error(code: StatusCode, msg: &str) -> BoxedFuture {
    http_error2(code, code, msg)
}

fn http_error2(outer_code: StatusCode, inner_code: StatusCode, msg: &str) -> BoxedFuture {
    let body = json!({
        "error": {
            "code":     inner_code.as_u16(),
            "message":  msg,
        }
    });
    let body = body.to_string() + "\n";

    let r = Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .status(outer_code)
        .body(body.into()).unwrap();
    Box::new(future::ok(r))
}

fn http_result(code: StatusCode, msg: &serde_json::Value) -> BoxedFuture {
    let body = json!({
        "result": msg
    });
    let body = body.to_string() + "\n";

    let r = Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .status(code)
        .body(body.into()).unwrap();
    Box::new(future::ok(r))
}

#[derive(Clone,Debug)]
struct Webnis {
    inner: Arc<WebnisInner>,
}

#[derive(Debug)]
struct WebnisInner {
    matcher:    Matcher,
    config:     config::Config,
}

// Create a new Webnis instance.
impl Webnis {
    pub fn new(matcher: Matcher, config: config::Config) -> Webnis {
        Webnis {
            inner: Arc::new(WebnisInner{
                matcher:    matcher,
                config:     config,
            })
        }
    }
}

type BoxedError = Box<::std::error::Error + Send + Sync>;
type BoxedFuture = Box<Future<Item=Response<Body>, Error=BoxedError> + Send>;

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

        // see if we know this route.
        let mat = match self.inner.matcher.match_req(&mut req) {
            None => return http_error(StatusCode::NOT_FOUND, "Not Found"),
            Some(m) => m,
        };
        let domain = match mat.route_param("domain") {
            None => return http_error(StatusCode::NOT_FOUND, "Not Found"),
            Some(d) => d,
        };

        // is it for a domain we serve?
        let domdef = match self.inner.config.domain.iter().find(|n| n.name == domain) {
            None => return http_error(StatusCode::NOT_FOUND, "No such domain"),
            Some(d) => d,
        };

        // auth or map lookup ?
        match mat.label() {
            Some("auth") => {
                // authenticate.
                self.auth(domdef, &mat)
            },
            Some("map") => {
                // find the map definition and the key.
                let (map, key, val) = match self.find_map(domdef, &mat) {
                    Err(e) => return e,
                    Ok(v) => v,
                };

                // query the database.
                self.serve_map(domdef, map, key, val)
            },
            _ => {
                // never happens
                http_error(StatusCode::INTERNAL_SERVER_ERROR, "wut?")
            },
        }
    }
}

impl Webnis {

    // authenticate.
    fn auth<'a, 'b>(&'a self, domain: &config::Domain, mat: &'b Match) -> BoxedFuture {

        // Get query parameters.
        let (login, password) = match (mat.query_param("login"), mat.query_param("password")) {
            (Some(l), Some(p)) => (l, p),
            _ => return http_error(StatusCode::BAD_REQUEST, "Query parameters missing"),
        };

        // Domain has "auth=x", now find auth "x" in the main config.
        let auth = match domain.auth.as_ref().and_then(|a| self.inner.config.auth.get(a)) {
            None => return http_error(StatusCode::NOT_FOUND, "Authentication not enabled"),
            Some(a) => a,
        };

        // Now auth says "map=y" and "key=z" which means we have to find the
        // map named "y" that supports lookup key "z".
        let mut map : Option<&config::Map> = None;
        let maps = self.inner.config.map_.get(&auth.map);
        if let Some(maps) = maps {
            for m in maps.iter() {
                if m.key.iter().chain(m.keys.iter()).find(|ref k| **k == &auth.key).is_some() {
                    map = Some(m);
                    break;
                }
            }
        }
        let map = match map {
            None => return http_error(StatusCode::NOT_FOUND, "Associated auth map not found"),
            Some(m) => m,
        };

        // And auth on this map.
        self.auth_map(domain, map, &auth.key, login, password)
    }

    // find the map we want to serve.
    fn find_map<'a, 'b>(&'a self, domain: &config::Domain, mat: &'b Match) -> Result<(&'a config::Map, &'a str, &'b str), BoxedFuture> {

        // Get mapname query parameter. Can't really fail, there is no
        // route definition without :map.
        let mapname = match mat.route_param("map") {
            None => return Err(http_error(StatusCode::NOT_FOUND, "Not found")),
            Some(m) => m,
        };

        // See if this map is allowed.
        if domain.maps.iter().find(|m| m.as_str() == mapname).is_none() {
            return Err(http_error(StatusCode::NOT_FOUND, "No such map"));
        }

        // find map definition.
        let maps = match self.inner.config.map_.get(mapname) {
            None => return Err(http_error(StatusCode::NOT_FOUND, "No such map")),
            Some(m) => m,
        };

        // mapdef can hold multiple maps- e.g. passwd.byname, passwd.byuid.
        // we distinguish between them based on the name of the key queryparam
        // (e.g. passwd?name=mike vs passwd?uid=1000)
        for map in maps.iter() {

            // see if one of the query parameters is a valid key name.
            // FIXME: this is likely not very efficient
            if let Some((key, val)) = map.key.iter()
                                        .chain(map.keys.iter())
                                        .chain(map.key_alias.keys())
                                        .map(|k| (map.key_alias.get(k).unwrap_or(k), k))
                                        .map(|(a, k)| (a, mat.query_param(k)))
                                        .find(|(_, v)| v.is_some()) {
                return Ok((map, key, val.unwrap()));
            }
        }

        Err(http_error(StatusCode::BAD_REQUEST, "No valid key parameter found"))
    }

    fn lookup_gdbm_map(&self, dom: &config::Domain, map: &config::Map, keyval: &str) -> Result<serde_json::Value, BoxedFuture> {
        let format = match map.map_format {
            None => return Err(http_error(StatusCode::INTERNAL_SERVER_ERROR, "Map format not set")),
            Some(ref s) => s,
        };
        let path = format!("{}/{}", dom.db_dir, map.map_file);
        let line = match db::gdbm_lookup(&path, keyval) {
            Err(DbError::NotFound) => return Err(http_error(StatusCode::NOT_FOUND, "No such key in map")),
            Err(DbError::MapNotFound) => return Err(http_error(StatusCode::NOT_FOUND, "No such map")),
            Err(DbError::Other) => return Err(http_error(StatusCode::INTERNAL_SERVER_ERROR, "Error reading database")),
            Ok(r) => r,
        };

        format::line_to_json(&line, &format).map_err(|_| http_error(StatusCode::INTERNAL_SERVER_ERROR, "Error in json serialization"))
    }

    fn serve_gdbm_map(&self, dom: &config::Domain, map: &config::Map, keyval: &str) -> BoxedFuture {
        let jv = match self.lookup_gdbm_map(dom, map, keyval) {
            Ok(jv) => jv,
            Err(e) => return e,
        };
        http_result(StatusCode::OK, &jv)
    }

    fn lookup_json_map(&self, dom: &config::Domain, map: &config::Map, keyname:&str, keyval: &str) -> Result<serde_json::Value, BoxedFuture> {
        let path = format!("{}/{}", dom.db_dir, map.map_file);
        match db::json_lookup(path, keyname, keyval) {
            Err(DbError::NotFound) => return Err(http_error(StatusCode::NOT_FOUND, "No such key in map")),
            Err(DbError::MapNotFound) => return Err(http_error(StatusCode::NOT_FOUND, "No such map")),
            Err(DbError::Other) => return Err(http_error(StatusCode::INTERNAL_SERVER_ERROR, "Error reading database")),
            Ok(r) => Ok(r),
        }
    }

    fn serve_json_map(&self, dom: &config::Domain, map: &config::Map, keyname:&str, keyval: &str) -> BoxedFuture {
        let jv = match self.lookup_json_map(dom, map, keyname, keyval) {
            Ok(jv) => jv,
            Err(e) => return e,
        };
        http_result(StatusCode::OK, &jv)
    }

    fn serve_map(&self, dom: &config::Domain, map: &config::Map, keyname: &str, keyval: &str) -> BoxedFuture {
        match map.map_type.as_str() {
            "gdbm" => return self.serve_gdbm_map(dom, map, keyval),
            "json" => return self.serve_json_map(dom, map, keyname, keyval),
            _ => {},
        }
        http_error(StatusCode::INTERNAL_SERVER_ERROR, "Unsupported database format")
    }

    fn auth_map(&self, dom: &config::Domain, map: &config::Map, keyname: &str, keyval: &str, passwd: &str) -> BoxedFuture {
        // do map lookup.
        let res = match map.map_type.as_str() {
            "gdbm" => self.lookup_gdbm_map(dom, map, keyval),
            "json" => self.lookup_json_map(dom, map, keyname, keyval),
            _ => return http_error(StatusCode::INTERNAL_SERVER_ERROR, "Unsupported database format"),
        };
        // find the returned JSON
        let json = match res {
            Ok(jv) => jv,
            Err(e) => return e,
        };

        // extract password and auth.
        let ok = match json.get("passwd").map(|p| p.as_str()).unwrap_or(None) {
            None => false,
            Some(p) => pwhash::unix::verify(passwd, p),
        };
        if ok {
            http_result(StatusCode::OK, &json!({}))
        } else {
            http_error2(StatusCode::FORBIDDEN, StatusCode::UNAUTHORIZED, "Password incorrect")
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

