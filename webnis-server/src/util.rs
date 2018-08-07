use std;
use std::io;
use std::io::{Error,ErrorKind};
use std::path::Path;

use hyper::{header,Body,Response,StatusCode};
use http::header::{HeaderMap,HeaderValue};

use futures::{future,Future};

use serde_json;

use openssl::pkey::PKey;
use openssl::x509::X509;
use openssl::pkcs12::Pkcs12;
use openssl::stack::Stack;
use native_tls::{Identity,TlsAcceptor};

use base64;

pub(crate) type BoxedError = Box<::std::error::Error + Send + Sync>;
pub(crate) type BoxedFuture = Box<Future<Item=Response<Body>, Error=BoxedError> + Send>;

// helpers.
pub(crate) fn http_error(code: StatusCode, msg: &'static str) -> BoxedFuture {
    debug!("{}", msg);
    let msg = msg.to_string() + "\n";
    let r = Response::builder()
        .header(header::CONTENT_TYPE, "text/plain")
        .status(code)
        .body(msg.into()).unwrap();
    Box::new(future::ok(r))
}

// helpers.
pub(crate) fn http_unauthorized() -> BoxedFuture {
    debug!("401 Unauthorized");
    let r = Response::builder()
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"webnis\"")
        .status(StatusCode::UNAUTHORIZED)
        .body("Unauthorized - send basic auth\n".into()).unwrap();
    Box::new(future::ok(r))
}

pub(crate) fn json_error(outer_code: StatusCode, inner_code: Option<StatusCode>, msg: &str) -> BoxedFuture {
    let body = json!({
        "error": {
            "code":     inner_code.unwrap_or(outer_code.clone()).as_u16(),
            "message":  msg,
        }
    });
    debug!("{}", body);
    let body = body.to_string() + "\n";

    let r = Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .status(outer_code)
        .body(body.into()).unwrap();
    Box::new(future::ok(r))
}

pub(crate) fn json_result(code: StatusCode, msg: &serde_json::Value) -> BoxedFuture {
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

pub(crate) fn box_error(e: impl std::error::Error + Send + Sync + 'static) -> BoxedError {
    Box::new(e)
}

fn read_pems(key: impl AsRef<Path>, cert: impl AsRef<Path>, password: &str) -> io::Result<Vec<u8>> {
    let b = std::fs::read_to_string(key)?;
    let pkey = if password.len() > 0 {
		PKey::private_key_from_pem_passphrase(b.as_bytes(), password.as_bytes())
	} else {
		PKey::private_key_from_pem(b.as_bytes())
	}?;
    let b = std::fs::read_to_string(cert)?;
    let mut certs = X509::stack_from_pem(b.as_bytes())?;
    let cert = certs.remove(0);
    let mut stack = Stack::<X509>::new().unwrap();
    certs.into_iter().for_each(|x| stack.push(x).unwrap());
    let mut builder = Pkcs12::builder();
    builder.ca(stack);
    let nickname = "certfile";
    let pkcs12 = builder.build("", nickname, &pkey, &cert)?;
    Ok(pkcs12.to_der()?)
}

pub fn acceptor_from_pem_files(key: impl AsRef<Path>, cert: impl AsRef<Path>, password: &str) -> io::Result<TlsAcceptor> {
    let identity = read_pems(key, cert, password)?;
    let identity = Identity::from_pkcs12(&identity, "").map_err(|e| Error::new(ErrorKind::Other, e))?;
    TlsAcceptor::new(identity).map_err(|e| Error::new(ErrorKind::Other, e))
}

#[derive(Debug,PartialEq)]
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
    debug!("got basic auth {}", s);
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

