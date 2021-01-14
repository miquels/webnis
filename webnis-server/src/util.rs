use std::borrow::Cow;
use std::collections::HashMap;

use actix_web::http::header::{self, HeaderMap, HeaderValue};
use actix_web::http::StatusCode;
use actix_web::HttpResponse;

use base64;
use percent_encoding::{percent_decode, utf8_percent_encode, PATH_SEGMENT_ENCODE_SET};
use pwhash;
use serde_json::{self, json};
use serde::Deserialize;

use crate::config;

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
pub(crate) fn http_unauthorized(domain: &str, schema: Option<&String>) -> HttpResponse {
    debug!("401 Unauthorized");
    let mut resp = HttpResponse::Unauthorized();
    resp.header(header::CONTENT_TYPE, "text/plain");
    if let Some(schema) = schema {
        let wa = if schema.as_str() == "Basic" {
            format!("{} realm=\"{}\"", schema, domain)
        } else {
            schema.to_owned()
        };
        resp.header(header::WWW_AUTHENTICATE, wa);
    }
    resp.body("Unauthorized - send credentials\n")
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
    let body = json!({ "result": msg });
    let body = body.to_string() + "\n";

    HttpResponse::build(code)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
}

pub(crate) fn json_result_raw(code: StatusCode, raw: &serde_json::Value) -> HttpResponse {
    let body = json!(raw);
    let body = body.to_string() + "\n";

    HttpResponse::build(code)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
}

/// decode POST body into simple key/value.
///
/// Now wouldn't it be great if we could use serde_urlencoded! Unfortunately
/// there's no support for non-UTF8 strings (nope, OsString / Vec<u8> do not work)
pub fn decode_post_body(body: &[u8]) -> HashMap<String, String> {
    let mut hm = HashMap::new();

    for kv in body.split(|&b| b == b'&') {
        let mut w = kv.splitn(2, |&b| b == b'=');
        let (k, v) = (w.next().unwrap(), w.next().unwrap_or(b""));
        if let Ok(k) = percent_decode(k).decode_utf8() {
            // don't percent-decode the password value.
            let v = match k.as_ref() {
                "password" => std::str::from_utf8(v).map(|s| s.to_string()),
                "password_raw" => continue,
                _ => percent_decode(v).decode_utf8().map(|x| x.into_owned()),
            };
            if let Ok(v) = v {
                hm.insert(k.into_owned(), v);
            }
        }
    }
    hm
}

pub(crate) fn check_unix_password(passwd: &str, pwhash: &str) -> bool {
    // we never allow DES hashes passwords. Sorry.
    if pwhash.len() == 13 && !pwhash.starts_with("$") {
        return false;
    }
    let pwbytes: Cow<[u8]> = percent_decode(passwd.as_bytes()).into();
    pwhash::unix::verify(pwbytes, pwhash)
}

/// Login / password from POST body.
#[derive(Deserialize)]
pub struct AuthInfo {
    pub username: String,
    pub password: String,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl AuthInfo {
    /// Decode POST body into a AuthInfo struct
    pub fn from_post_body(body: &[u8], is_json: bool) -> Option<AuthInfo> {
        if is_json {
            if let Ok(mut ai) = serde_json::from_slice::<AuthInfo>(body) {
                if let Cow::Owned(p) = utf8_percent_encode(&ai.password, PATH_SEGMENT_ENCODE_SET).into() {
                    ai.password = p;
                }
                ai.extra.remove("password_raw");
                return Some(ai);
            }
            return None;
        }
        let mut hm = decode_post_body(body);
        let username = hm.remove("username")?;
        let password = hm.remove("password")?;
        let mut extra = HashMap::new();
        for (k, v) in hm.into_iter() {
            extra.insert(k, json!(v));
        }
        Some(AuthInfo {
            username,
            password,
            extra,
        })
    }
}

#[derive(Debug, PartialEq)]
/// Result from check_http_auth
pub enum AuthResult {
    // no (matching) authorization header
    NoAuth,
    // login incorrect
    BadAuth,
    // come on in
    AuthOk,
}

/// Check http authentication.
pub fn check_http_auth(hdrs: &HeaderMap<HeaderValue>, domain: &config::Domain) -> AuthResult {
    // Get authschema from config. Not set? Access allowed.
    let schema = match domain.http_authschema {
        Some(ref s) => s.as_str(),
        None => return AuthResult::AuthOk,
    };

    // Get authtoken from config. Not set? Access denied.
    let token = match domain.http_authtoken {
        Some(ref t) => t.as_str(),
        None => {
            debug!("check_http_auth: domain {}: http_authtoken not set", domain.name);
            return AuthResult::BadAuth;
        },
    };

    // find Authorization header and transform into &str
    let hdr = match hdrs.get(header::AUTHORIZATION).map(|v| v.to_str()) {
        Some(Ok(h)) => h,
        _ => return AuthResult::NoAuth,
    };

    // split and check that first word matches the required authschema.
    let w = hdr.split_whitespace().collect::<Vec<&str>>();
    if w.len() < 2 || w[0] != schema {
        return AuthResult::NoAuth;
    }

    // if encoding is set, decode.
    let httptoken = match domain.http_authencoding.as_ref().map(|s| s.as_str()) {
        Some("base64") => {
            // base64 decode 2nd word
            match base64::decode(w[1]).ok().and_then(|v| String::from_utf8(v).ok()) {
                None => return AuthResult::BadAuth,
                Some(v) => Cow::from(v),
            }
        },
        Some(_) => {
            debug!("check_http_auth: domain {}: unknown httpencoding", domain.name);
            return AuthResult::BadAuth;
        },
        None => Cow::from(w[1]),
    };

    // Must match token.
    if httptoken == token {
        AuthResult::AuthOk
    } else {
        AuthResult::BadAuth
    }
}
