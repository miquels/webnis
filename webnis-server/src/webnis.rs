use std::sync::Arc;
use std::collections::HashMap;

use serde_json;
use pwhash;

use errors::WnError;
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

        // perhaps it's LUA auth?
        if let Some(ref lua_func) = auth.lua_function {
            let lauth = lua::AuthInfo{
                username:       authinfo.username,
                pct_password:   lua::bytes_to_string(&authinfo.password),
                map:            auth.map.clone(),
                key:            auth.key.clone(),
            };
            let res = match lua::lua_auth(lua_func, &domain.name, lauth) {
                Ok(serde_json::Value::Null) => json_error(StatusCode::FORBIDDEN, Some(StatusCode::UNAUTHORIZED), "Password incorrect"),
                Ok(v) => json_result(StatusCode::OK, &v),
                Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Internal server error"),
            };
            return res;
        }

        let auth_map = auth.map.as_ref().unwrap();
        let auth_key = auth.key.as_ref().unwrap();
        match self.auth_map(domain, auth_map, auth_key, &authinfo.username, &authinfo.password) {
            Ok(true) => json_result(StatusCode::OK, &json!({})),
            Ok(false) => json_error(StatusCode::FORBIDDEN, Some(StatusCode::UNAUTHORIZED), "Password incorrect"),
            Err(WnError::MapNotFound) => return json_error(StatusCode::NOT_FOUND, None, "Associated auth map not found"),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Internal server error"),
        }
    }

    /// Authenticate using a map. We find the map, lookup the keyname/keyval (usually username).
    /// Then if we found an entry, it is a map, and it has a "passwd" member, check the
    /// provided password against the password in the map.
    fn auth_map(&self, dom: &config::Domain, map: &str, key: &str, username: &str, passwd: &[u8]) -> Result<bool, WnError> {

        let (map, keyname) = match self.inner.config.find_map(map, key) {
            None => {
                warn!("auth_map: map {} with key {} not found", map, key);
                return Err(WnError::MapNotFound);
            },
            Some(m) => m,
        };

        // see what type of map this is and delegate to the right lookup function.
        let res = match map.map_type.as_str() {
            "gdbm" => self.lookup_gdbm_map(dom, map, username),
            "json" => self.lookup_json_map(dom, map, keyname, username),
            _ => {
                warn!("auth_map: map {}: unsupported {}", map.name, map.map_type);
                return Err(WnError::DbOther);
            },
        };

        // did the lookup succeed?
        let json = match res {
            Ok(jv) => jv,
            Err(WnError::KeyNotFound) => return Ok(false),
            Err(e) => return Err(e),
        };

        // extract password and auth.
        let res = match json.get("passwd").map(|p| p.as_str()).unwrap_or(None) {
            None => false,
            Some(p) => pwhash::unix::verify(passwd, p),
        };
        Ok(res)
    }

    /// This basically is the lua map_auth() function.
    pub fn lua_map_auth(&self, domain: &str, map: &str, key: &str, username: &str, passwd: &[u8]) -> Result<bool, WnError> {

        // lookup domain in config
        let domain = match self.inner.config.find_domain(&domain) {
            None => return Err(WnError::DbOther),
            Some(d) => d,
        };

        self.auth_map(domain, map, key, username, passwd)
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
            Err(WnError::KeyNotFound) => json_error(StatusCode::NOT_FOUND, None, "No such key in map"),
            Err(WnError::MapNotFound) => json_error(StatusCode::NOT_FOUND, None, "No such map"),
            Err(WnError::UnknownFormat) => json_error(StatusCode::NOT_FOUND, None, "Unknown map format"),
            Err(WnError::SerializeJson(_)) => json_error(StatusCode::NOT_FOUND, None, "Serialize error"),
            Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, None, "Error reading database"),
            Ok(r) => json_result(StatusCode::OK, &r),
        }
    }

    /// This basically is the lua map_lookup() function. Note that it
    /// returns json Null if the key is not found.
    pub fn lua_map_lookup(&self, domain: &str, mapname: &str, keyname: &str, keyval: &str) -> Result<serde_json::Value, WnError> {

        // lookup domain in config
        let domain = match self.inner.config.find_domain(&domain) {
            None => return Err(WnError::DbOther),
            Some(d) => d,
        };

        // find the map 
        let (map, keyname) = match self.inner.config.find_map(mapname, keyname) {
            None => return Err(WnError::DbOther),
            Some(m) => m,
        };

        // do lookup
        let res = match map.map_type.as_str() {
            "gdbm" => self.lookup_gdbm_map(domain, map, keyval),
            "json" => self.lookup_json_map(domain, map, keyname, keyval),
            _ => Err(WnError::Other),
        };

        // remap KeyNotFound error to json null
        match res {
            Err(WnError::KeyNotFound) => Ok(json!(null)),
            x => x,
        }
    }

    fn lookup_gdbm_map(&self, dom: &config::Domain, map: &config::Map, keyval: &str) -> Result<serde_json::Value, WnError> {
        let format = match map.map_format {
            None => return Err(WnError::UnknownFormat),
            Some(ref s) => s,
        };
        let path = format!("{}/{}", dom.db_dir, map.map_file.as_ref().unwrap());
        let line = db::gdbm_lookup(&path, keyval)?;
        format::line_to_json(&line, &format, &map.map_args)
    }

    fn lookup_json_map(&self, dom: &config::Domain, map: &config::Map, keyname: &str, keyval: &str) -> Result<serde_json::Value, WnError> {
        let path = format!("{}/{}", dom.db_dir, map.map_file.as_ref().unwrap());
        db::json_lookup(path, keyname, keyval)
    }

    fn lookup_lua_map(&self, dom: &config::Domain, map: &config::Map, keyname: &str, keyval: &str) -> Result<serde_json::Value, WnError> {
        match lua::lua_map(&map.lua_function.as_ref().unwrap(), &dom.name, keyname, keyval) {
            Ok(m) => Ok(m),
            Err(_) => Err(WnError::Other),
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

