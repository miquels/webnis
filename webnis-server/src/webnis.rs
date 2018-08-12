use std::sync::Arc;
use std::collections::HashMap;

use serde_json;
use pwhash;

use db::DbError;
use super::util::*;
use super::config;
use super::db;
use super::format;
use super::lua;

use actix_web::HttpResponse;
use actix_web::http::StatusCode;

#[derive(Clone,Debug)]
pub(crate) struct Webnis {
    pub inner: Arc<WebnisInner>,
}

#[derive(Debug)]
pub(crate) struct WebnisInner {
    pub config:     config::Config,
}

// Create a new Webnis instance.
impl Webnis {
    pub fn new(config: config::Config) -> Webnis {
        Webnis {
            inner: Arc::new(WebnisInner{
                config:     config,
            })
        }
    }
}

impl Webnis {

    // authenticate user
    pub fn handle_auth(&self, domain: String, body: Vec<u8>) -> HttpResponse {

        // lookup domain in config
        let domain = match self.inner.config.find_domain(&domain) {
            None => return json_error(StatusCode::BAD_REQUEST, None, "Domain not found"),
            Some(d) => d,
        };

        // get username/password from POST body
        let authinfo = match AuthInfo::from_post_body(&body) {
            None => return json_error(StatusCode::BAD_REQUEST, None, "Body parameters missing"),
            Some(ai) => ai,
        };

        // Domain has "auth=x", now find auth "x" in the main config.
        let auth = match domain.auth.as_ref().and_then(|a| self.inner.config.auth.get(a)) {
            None => return json_error(StatusCode::NOT_FOUND, None, "Authentication not enabled"),
            Some(a) => a,
        };

        // find the map 
        let (map, key) = match self.inner.config.find_map(&auth.map, &auth.key) {
            None => return json_error(StatusCode::NOT_FOUND, None, "Associated auth map not found"),
            Some(m) => m,
        };

        // And auth on this map.
        self.auth_map(domain, map, key, &authinfo.username, &authinfo.password)
    }

    // authenticate user using mao.
    fn auth_map(&self, dom: &config::Domain, map: &config::Map, keyname: &str, keyval: &str, passwd: &[u8]) -> HttpResponse {

        // do map lookup.
        let res = match map.map_type.as_str() {
            "gdbm" => self.lookup_gdbm_map(dom, map, keyval),
            "json" => self.lookup_json_map(dom, map, keyname, keyval),
            _ => return json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Unsupported database format"),
        };
        // find the returned JSON
        let json = match res {
            Ok(jv) => jv,
            Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "No such key in map"),
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

    // look something up in a map.
    pub fn handle_map(&self, domain: &str, map: &str, query: &HashMap<String, String>) -> HttpResponse {

        // lookup domain in config
        let domain = match self.inner.config.find_domain(&domain) {
            None => return json_error(StatusCode::BAD_REQUEST, None, "Domain not found"),
            Some(d) => d,
        };

        // Simply use the first query parameter.
        let (keyname, keyval) = match query.iter().next() {
            None => return json_error(StatusCode::BAD_REQUEST, None, "Query params missing"),
            Some(kv) => kv,
        };

        // find the map 
        let (map, keyname) = match self.inner.config.find_allowed_map(&domain, map, keyname) {
            None => return json_error(StatusCode::NOT_FOUND, None, "No such map"),
            Some(m) => m,
        };

        let res = match map.map_type.as_str() {
            "gdbm" => self.lookup_gdbm_map(domain, map, keyval),
            "json" => self.lookup_json_map(domain, map, keyname, keyval),
            "lua" => self.lookup_lua_map(domain, map, keyname, keyval),
            _ => return json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Unsupported database format"),
        };
        match res {
            Err(DbError::NotFound) => json_error(StatusCode::NOT_FOUND, None, "No such key in map"),
            Err(DbError::MapNotFound) => json_error(StatusCode::NOT_FOUND, None, "No such map"),
            Err(DbError::UnknownFormat) => json_error(StatusCode::NOT_FOUND, None, "Unknown map format"),
            Err(DbError::SerializeJson) => json_error(StatusCode::NOT_FOUND, None, "Serialize error"),
            Err(DbError::Other) => json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Error reading database"),
            Ok(r) => json_result(StatusCode::OK, &r),
        }
    }

    pub fn map_lookup(&self, domain: &str, mapname: &str, keyname: &str, keyval: &str) -> Result<serde_json::Value, DbError> {

        // lookup domain in config
        // XXX FIXME second time we do this lookup. we need to start carrying some per-request state.
        let domain = match self.inner.config.find_domain(&domain) {
            None => return Err(DbError::Other),
            Some(d) => d,
        };

        // find the map 
        let (map, keyname) = match self.inner.config.find_map(mapname, keyname) {
            None => return Err(DbError::Other),
            Some(m) => m,
        };

        // do lookup
        match map.map_type.as_str() {
            "gdbm" => self.lookup_gdbm_map(domain, map, keyval),
            "json" => self.lookup_json_map(domain, map, keyname, keyval),
            _ => Err(DbError::Other),
        }
    }

    fn lookup_gdbm_map(&self, dom: &config::Domain, map: &config::Map, keyval: &str) -> Result<serde_json::Value, DbError> {
        let format = match map.map_format {
            None => return Err(DbError::UnknownFormat),
            Some(ref s) => s,
        };
        let path = format!("{}/{}", dom.db_dir, map.map_file);
        let line = db::gdbm_lookup(&path, keyval)?;
        format::line_to_json(&line, &format).map_err(|_| DbError::SerializeJson)
    }

    fn lookup_json_map(&self, dom: &config::Domain, map: &config::Map, keyname: &str, keyval: &str) -> Result<serde_json::Value, DbError> {
        let path = format!("{}/{}", dom.db_dir, map.map_file);
        db::json_lookup(path, keyname, keyval)
    }

    fn lookup_lua_map(&self, dom: &config::Domain, map: &config::Map, keyname: &str, keyval: &str) -> Result<serde_json::Value, DbError> {
        match lua::lua_map(&map.map_file, &dom.name, keyname, keyval) {
            Ok(m) => Ok(m),
            Err(e) => Err(DbError::Other),
        }
    }

    // lookup the password for this domain
    pub fn domain_password<'a>(&'a self, domain: &str) -> Option<&'a str> {
        match self.inner.config.find_domain(domain) {
            None => None,
            Some(d) => d.password.as_ref().map(|s| s.as_str()),
        }
    }
}

