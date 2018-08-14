use std;
use std::collections::HashMap;

use actix_web::HttpResponse;
use actix_web::http::{StatusCode};
use actix_web::http::header::{self,HeaderMap,HeaderValue};

use percent_encoding::percent_decode;

use serde_json;

use base64;

//pub(crate) type BoxedError = Box<::std::error::Error>;
//pub(crate) type BoxedFuture = Box<Future<Item=HttpResponse, Error=BoxedError>>;
//
//pub(crate) fn box_error(e: impl std::error::Error + Send + Sync + 'static) -> BoxedError {
//    Box::new(e)
//}

// helpers.
pub(crate) fn http_error(code: StatusCode, msg: &'static str) -> HttpResponse {
    debug!("{}", msg);
    let msg = msg.to_string() + "\n";
    let mut builder = HttpResponse::build(code);
    if code.is_server_error() || code == StatusCode::FORBIDDEN {
        builder.force_close();
    }
    builder.header(header::CONTENT_TYPE, "text/plain");
    builder.body(msg)
}

// helpers.
pub(crate) fn http_unauthorized() -> HttpResponse {
    debug!("401 Unauthorized");
    HttpResponse::Unauthorized()
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"webnis\"")
        .body("Unauthorized - send basic auth\n")
}

pub(crate) fn json_error(outer_code: StatusCode, inner_code: Option<StatusCode>, msg: &str) -> HttpResponse {
    let body = json!({
        "error": {
            "code":     inner_code.unwrap_or(outer_code.clone()).as_u16(),
            "message":  msg,
        }
    });
    debug!("{}", body);
    let body = body.to_string() + "\n";

    HttpResponse::build(outer_code)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
}

pub(crate) fn json_result(code: StatusCode, msg: &serde_json::Value) -> HttpResponse {
    let body = json!({
        "result": msg
    });
    let body = body.to_string() + "\n";

    HttpResponse::build(code)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
}

/// decode POST body into simple key/value.
///
/// Now wouldn't it be great if we could use serde_urlencoded! Unfortunately
/// there's no support for non-UTF8 strings (nope, OsString / Vec<u8> do not work)
pub fn decode_post_body(body: &[u8]) -> HashMap<String, Vec<u8>> {
    let mut hm = HashMap::new();

    for kv in body.split(|&b| b == b'&') {
        let mut w = kv.splitn(2, |&b| b == b'=');
        let (k, v) = (w.next().unwrap(), w.next().unwrap_or(b""));
        let k = percent_decode(k).if_any().unwrap_or(k.to_vec());
        let v = percent_decode(v).if_any().unwrap_or(v.to_vec());
        if let Ok(k) = String::from_utf8(k) {
            hm.insert(k, v);
        }
    }
    hm
}

/// Login / password from POST body.
pub struct AuthInfo {
    pub username:   String,
    pub password:   Vec<u8>,
}
    
impl AuthInfo {
    /// Decode POST body into a AuthInfo struct
    pub fn from_post_body(body: &[u8]) -> Option<AuthInfo> {
        let hm = decode_post_body(body);
        let username = std::str::from_utf8(hm.get("username")?).ok()?.to_string();
        let password = hm.get("password")?.to_vec();
        Some(AuthInfo{ username, password })
    }
}

#[derive(Debug,PartialEq)]
/// Result from check_basic_auth
pub enum AuthResult {
    // no (matching) authorization header
    NoAuth,
    // login incorrect
    BadAuth,
    // come on in
    AuthOk,
}

/// Check basic authentication.
pub fn check_basic_auth(hdrs: &HeaderMap<HeaderValue>, login: Option<&str>, password: Option<&str>) -> AuthResult {
    // find header and transform into &str
    let hdr = match hdrs.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        None => return AuthResult::NoAuth,
        Some(h) => h,
    };
    // split and check that first word is 'Basic'
    let w = hdr.split_whitespace().collect::<Vec<&str>>();
    if w.len() < 2 || w[0] != "Basic" {
        return AuthResult::NoAuth;
    }
    // base64 decode 2nd word and transform into String.
    let s = match base64::decode(w[1]).ok().and_then(|v| String::from_utf8(v).ok()) {
        None => return AuthResult::BadAuth,
        Some(v) => v,
    };
    // split into name and password.
    let w = s.splitn(2, ':').collect::<Vec<&str>>();
    if w.len() != 2 {
        return AuthResult::BadAuth;
    }
    // what is set must match
    match login.map(|l| l == w[0]).unwrap_or(true) &&
            password.map(|p| p == w[1]).unwrap_or(true) {
        true => AuthResult::AuthOk,
        false => AuthResult::BadAuth,
    }
}

