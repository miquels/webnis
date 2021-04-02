use std::borrow::Cow;
use std::collections::HashMap;

use base64;
use http::{Response, StatusCode};
use hyper::body::Body;
use percent_encoding::{percent_decode, utf8_percent_encode, PATH_SEGMENT_ENCODE_SET};
use pwhash;
use serde_json::json;
use serde::Deserialize;
use warp::Rejection;
use warp::reply::Reply;

type WarpResult = Result<warp::reply::Response, warp::Rejection>;

use crate::config;

fn stringnl(msg: impl Into<String>) -> String {
    let mut msg = msg.into();
    if !msg.ends_with("\n") {
        msg.push('\n');
    }
    msg
}

pub(crate) enum Reject {
    Status(StatusCode, String),
    Unauthorized(Option<String>),
    JsonError(StatusCode, String),
}

impl warp::reject::Reject for Reject {}

impl std::fmt::Debug for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_tuple("Reject");
        match self {
            &Reject::Status(ref c, ref s) => dbg.field(c).field(s).finish(),
            &Reject::JsonError(ref c, ref j) => dbg.field(c).field(j).finish(),
            &Reject::Unauthorized(ref s) => {
                match s.as_ref() {
                   Some(s) => dbg.field(&StatusCode::UNAUTHORIZED).field(s).finish(),
                   None => dbg.field(&StatusCode::UNAUTHORIZED).finish(),
                }
            },
        }
    }
}

impl Reject {
    pub(crate) async fn handle_rejection(err: Rejection) -> Result<impl Reply, Rejection> {
        let this = match err.find::<Reject>() {
            Some(reject) => reject,
            None => return Err(err),
        };
        let resp = match this {
            Reject::Status(status, msg) => {
                Response::builder()
                    .status(status)
                    .header("content-type", "text/plain")
                    .body(Body::from(stringnl(msg)))
            },
            Reject::JsonError(status, json) => {
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(stringnl(json)))
            },
            Reject::Unauthorized(schema) => {
                let mut builder = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "text/plain");
                if let Some(schema) = schema {
                    builder = builder.header("www-authenticate", schema);
                }
                builder.body(Body::from("credentials missing\n"))
            },
        }.map_err(http_to_reject)?;
        Ok(resp)
    }

    pub fn status(status: StatusCode, msg: impl Into<String>) -> Rejection {
        warp::reject::custom(Self::Status(status, stringnl(msg)))
    }
}

fn http_to_reject(err: http::Error) -> Rejection {
    let r: Reject = err.into();
    r.into()
}

impl From<http::Error> for Reject {
    fn from(err: http::Error) -> Reject {
        Reject::Status(StatusCode::INTERNAL_SERVER_ERROR, stringnl(err.to_string()))
    }
}

/*
impl From<Reject> for Rejection {
    fn from(reject: Reject) -> Rejection {
        warp::reject::custom(reject)
    }
}*/

// helpers.
pub(crate) fn http_unauthorized(domain: &str, schema: Option<&String>) -> Rejection {
    debug!("401 Unauthorized");
    let wa = schema.map(|schema| {
        let s = if schema.as_str() == "Basic" {
            format!("{} realm=\"{}\"", schema, domain)
        } else {
            schema.to_owned()
        };
	stringnl(s)
    });
    warp::reject::custom(Reject::Unauthorized(wa))
}

pub(crate) fn json_error(outer_code: StatusCode, inner_code: Option<StatusCode>, msg: &str) -> Rejection {
    let body = json!({
        "error": {
            "code":     inner_code.unwrap_or(outer_code.clone()).as_u16(),
            "message":  msg,
        }
    });
    debug!("{}", body);
    warp::reject::custom(Reject::JsonError(outer_code, stringnl(body.to_string())))
}

pub(crate) fn json_result(code: StatusCode, msg: &serde_json::Value) -> WarpResult {
    let body = stringnl(json!({ "result": msg }).to_string());

    Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .map_err(http_to_reject)
}

pub(crate) fn json_result_raw(code: StatusCode, raw: &serde_json::Value) -> WarpResult {
    let body = stringnl(json!(raw).to_string());

    Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .map_err(http_to_reject)
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
pub fn check_http_auth(authz: Option<String>, domain: &config::Domain) -> AuthResult {
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

    // We must have an authorization header,
    let hdr = match authz {
        Some(h) => h,
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
