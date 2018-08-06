use std::sync::Arc;

use futures::future;
use hyper::{Body, Request, StatusCode};
use serde_json;
use pwhash;

use routematcher::{Matcher,Match};
use db::DbError;
use super::util::*;
use super::config;
use super::db;
use super::format;

#[derive(Clone,Debug)]
pub(crate) struct Webnis {
    pub inner: Arc<WebnisInner>,
}

#[derive(Debug)]
pub(crate) struct WebnisInner {
    pub matcher:    Matcher,
    pub config:     config::Config,
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

impl Webnis {

    pub fn serve<'a>(&mut self, mut req: Request<Body>) -> BoxedFuture {

        // see if we know this route.
        let mat = match self.inner.matcher.match_req_resp(&mut req) {
            Err(resp) => return Box::new(future::ok(resp)),
            Ok(m) => m,
        };

        let domain = match mat.route_param("domain") {
            None => return http_error(StatusCode::NOT_FOUND, "Not Found"),
            Some(d) => d,
        };

        // is it for a domain we serve?
        let domdef = match self.inner.config.domain.iter().find(|n| n.name == domain) {
            None => return json_error(StatusCode::NOT_FOUND, None, "No such domain"),
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
                http_error(StatusCode::INTERNAL_SERVER_ERROR, "This did not happen (well not again)")
            },
        }
    }

    // authenticate.
    pub fn auth<'a, 'b>(&'a self, domain: &config::Domain, mat: &'b Match) -> BoxedFuture {

        // Get query parameters.
        // XXX FIXME password should be Vec<u8> really since we cannot assume it's valid utf8!
        let (login, password) = match (mat.body_param("login"), mat.body_param_bytes("password")) {
            (Some(l), Some(p)) => (l, p),
            _ => return json_error(StatusCode::BAD_REQUEST, None, "Body parameters missing"),
        };

        // Domain has "auth=x", now find auth "x" in the main config.
        let auth = match domain.auth.as_ref().and_then(|a| self.inner.config.auth.get(a)) {
            None => return json_error(StatusCode::NOT_FOUND, None, "Authentication not enabled"),
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
            None => return json_error(StatusCode::NOT_FOUND, None, "Associated auth map not found"),
            Some(m) => m,
        };

        // And auth on this map.
        self.auth_map(domain, map, &auth.key, login, password)
    }

    // find the map we want to serve.
    pub fn find_map<'a, 'b>(&'a self, domain: &config::Domain, mat: &'b Match) -> Result<(&'a config::Map, &'a str, &'b str), BoxedFuture> {

        // Get mapname query parameter. Can't really fail, there is no
        // route definition without :map.
        let mapname = match mat.route_param("map") {
            None => return Err(json_error(StatusCode::NOT_FOUND, None, "Not found")),
            Some(m) => m,
        };

        // See if this map is allowed.
        if domain.maps.iter().find(|m| m.as_str() == mapname).is_none() {
            return Err(json_error(StatusCode::NOT_FOUND, None, "No such map"));
        }

        // find map definition.
        let maps = match self.inner.config.map_.get(mapname) {
            None => return Err(json_error(StatusCode::NOT_FOUND, None, "No such map")),
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

        Err(json_error(StatusCode::BAD_REQUEST, None, "No valid key parameter found"))
    }

    pub fn lookup_gdbm_map(&self, dom: &config::Domain, map: &config::Map, keyval: &str) -> Result<serde_json::Value, BoxedFuture> {
        let format = match map.map_format {
            None => return Err(json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Map format not set")),
            Some(ref s) => s,
        };
        let path = format!("{}/{}", dom.db_dir, map.map_file);
        let line = match db::gdbm_lookup(&path, keyval) {
            Err(DbError::NotFound) => return Err(json_error(StatusCode::NOT_FOUND, None, "No such key in map")),
            Err(DbError::MapNotFound) => return Err(json_error(StatusCode::NOT_FOUND, None, "No such map")),
            Err(DbError::Other) => return Err(json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Error reading database")),
            Ok(r) => r,
        };

        format::line_to_json(&line, &format).map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Error in json serialization"))
    }

    pub fn serve_gdbm_map(&self, dom: &config::Domain, map: &config::Map, keyval: &str) -> BoxedFuture {
        let jv = match self.lookup_gdbm_map(dom, map, keyval) {
            Ok(jv) => jv,
            Err(e) => return e,
        };
        json_result(StatusCode::OK, &jv)
    }

    pub fn lookup_json_map(&self, dom: &config::Domain, map: &config::Map, keyname:&str, keyval: &str) -> Result<serde_json::Value, BoxedFuture> {
        let path = format!("{}/{}", dom.db_dir, map.map_file);
        match db::json_lookup(path, keyname, keyval) {
            Err(DbError::NotFound) => return Err(json_error(StatusCode::NOT_FOUND, None, "No such key in map")),
            Err(DbError::MapNotFound) => return Err(json_error(StatusCode::NOT_FOUND, None, "No such map")),
            Err(DbError::Other) => return Err(json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Error reading database")),
            Ok(r) => Ok(r),
        }
    }

    pub fn serve_json_map(&self, dom: &config::Domain, map: &config::Map, keyname:&str, keyval: &str) -> BoxedFuture {
        let jv = match self.lookup_json_map(dom, map, keyname, keyval) {
            Ok(jv) => jv,
            Err(e) => return e,
        };
        json_result(StatusCode::OK, &jv)
    }

    pub fn serve_map(&self, dom: &config::Domain, map: &config::Map, keyname: &str, keyval: &str) -> BoxedFuture {
        match map.map_type.as_str() {
            "gdbm" => return self.serve_gdbm_map(dom, map, keyval),
            "json" => return self.serve_json_map(dom, map, keyname, keyval),
            _ => {},
        }
        json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Unsupported database format")
    }

    pub fn auth_map(&self, dom: &config::Domain, map: &config::Map, keyname: &str, keyval: &str, passwd: &[u8]) -> BoxedFuture {
        // do map lookup.
        let res = match map.map_type.as_str() {
            "gdbm" => self.lookup_gdbm_map(dom, map, keyval),
            "json" => self.lookup_json_map(dom, map, keyname, keyval),
            _ => return json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Unsupported database format"),
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
            json_result(StatusCode::OK, &json!({}))
        } else {
            json_error(StatusCode::FORBIDDEN, Some(StatusCode::UNAUTHORIZED), "Password incorrect")
        }
    }
}

