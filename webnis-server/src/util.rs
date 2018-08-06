use std;

use hyper::{header,Body,Response,StatusCode};
use futures::{future,Future};
use serde_json;

pub(crate) type BoxedError = Box<::std::error::Error + Send + Sync>;
pub(crate) type BoxedFuture = Box<Future<Item=Response<Body>, Error=BoxedError> + Send>;

// helpers.
pub(crate) fn http_error(code: StatusCode, msg: &'static str) -> BoxedFuture {
    let msg = msg.to_string() + "\n";
    let r = Response::builder()
        .header(header::CONTENT_TYPE, "text/plain")
        .status(code)
        .body(msg.into()).unwrap();
    Box::new(future::ok(r))
}

pub(crate) fn json_error(outer_code: StatusCode, inner_code: Option<StatusCode>, msg: &str) -> BoxedFuture {
    let body = json!({
        "error": {
            "code":     inner_code.unwrap_or(outer_code.clone()).as_u16(),
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

