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
extern crate routematcher;

mod config;
mod db;
mod format;

use std::net::ToSocketAddrs;
use std::process::exit;
use std::sync::Arc;

use futures::future;
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

    let config = config::read(cfg)?;
    if config.domain.len() == 0 {
        eprintln!("{}: no domains defined in {}", PROGNAME, cfg);
        exit(1);
    }

    // build the routes we're going to serve.
    let builder = Builder::new();
    if let Some(def_domain) = config.domain.iter().find(|d| d.is_default) {
        builder
            .add("/webnis/:map")
            .method(&Method::GET)
            .label(&def_domain.name);
    }
    builder
        .add("/webnis/:domain/:map")
        .method(&Method::GET);
    let matcher = builder.compile();
    let webnis = Webnis::new(matcher, config.clone());

    // start the servers.
    let mut servers = Vec::new();
    for sockaddr in config.server.listen.to_socket_addrs().unwrap() {
        println!("Listening on http://{:?}", sockaddr);
        let server = Server::try_bind(&sockaddr)?
            .tcp_nodelay(true)
            .serve(webnis.clone())
            .map_err(|e| eprintln!("server error: {}", e));
        servers.push(server);
    }

    // wait for all servers to finish.
    let fut = future::join_all(servers).then(|_| Ok(()));
    rt::run(fut);

    Ok(())
}

// helper.
fn http_error(code: StatusCode, msg: &str) -> BoxedFuture {
    let body = json!({
        "error": {
            "code":     code.as_u16(),
            "message":  msg,
        }
    });
    let body = body.to_string() + "\n";

    let r = Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .status(code)
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
        let domain = match mat.route_param("domain").or(mat.label()) {
            None => return http_error(StatusCode::NOT_FOUND, "Not Found"),
            Some(d) => d,
        };

        // is it for a domain we serve?
        let domdef = match self.inner.config.domain.iter().find(|n| n.name == domain) {
            None => return http_error(StatusCode::NOT_FOUND, "No such domain"),
            Some(d) => d,
        };

        // find the map definition and the key.
        let (map, key, val) = match self.find_map(domdef, &mat) {
            Err(e) => return e,
            Ok(v) => v,
        };

        // query the database.
        self.serve_map(domdef, map, key, val)
    }
}

impl Webnis {

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

    fn serve_gdbm_map(&self, dom: &config::Domain, map: &config::Map, keyval: &str) -> BoxedFuture {
        let format = match map.map_format {
            None => return http_error(StatusCode::INTERNAL_SERVER_ERROR, "Map format not set"),
            Some(ref s) => s,
        };
        let path = format!("{}/{}", dom.db_dir, map.map_file);
        let line = match db::gdbm_lookup(&path, keyval) {
            Err(DbError::NotFound) => return http_error(StatusCode::NOT_FOUND, "No such key in map"),
            Err(DbError::MapNotFound) => return http_error(StatusCode::NOT_FOUND, "No such map"),
            Err(DbError::Other) => return http_error(StatusCode::INTERNAL_SERVER_ERROR, "Error reading database"),
            Ok(r) => r,
        };

        let jv = match format::line_to_json(&line, &format) {
            Err(_) => return http_error(StatusCode::INTERNAL_SERVER_ERROR, "Error formatting reply"),
            Ok(j) => j,
        };
        http_result(StatusCode::OK, &jv)
    }

    fn serve_json_map(&self, dom: &config::Domain, map: &config::Map, keyname:&str, keyval: &str) -> BoxedFuture {
        let path = format!("{}/{}", dom.db_dir, map.map_file);
        let jv = match db::json_lookup(path, keyname, keyval) {
            Err(DbError::NotFound) => return http_error(StatusCode::NOT_FOUND, "No such key in map"),
            Err(DbError::MapNotFound) => return http_error(StatusCode::NOT_FOUND, "No such map"),
            Err(DbError::Other) => return http_error(StatusCode::INTERNAL_SERVER_ERROR, "Error reading database"),
            Ok(r) => r,
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
}

