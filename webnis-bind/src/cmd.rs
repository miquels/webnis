
use std::io;
use std::error::Error;

use serde_json;
use url::Url;
use hyper;
use hyper::Client;
use hyper_tls::HttpsConnector;
use hyper::StatusCode;

use futures::prelude::*;
use futures::future;

use super::Context;

pub(crate) enum Cmd {
    GetPwNam,
    GetPwUid,
    GetGrNam,
    GetGrGid,
    GetGidList,
}

/// Possible requests our clients can send us
struct Request<'a> {
    cmd:    Cmd,
    args:   Vec<&'a str>,
}

#[derive(Serialize,Deserialize)]
#[serde(untagged)]
enum Response {
    Success { result: serde_json::Value },
    Error { error: ResponseError },
}

#[derive(Serialize,Deserialize)]
struct ResponseError {
    code:       i64,
    message:    String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data:       Option<String>,
}

pub(crate) fn process(ctx: Context, line: String) -> Box<Future<Item=String, Error=io::Error> + Send> {
    match Request::parse(&line) {
        Ok(req) => Box::new(process2(ctx, req)),
        Err(e) => Box::new(future::ok(response_error(400, &e))),
    }
}

fn build_uri(cfg: &super::config::Config, map: &str, key: &str, val: &str) -> hyper::Uri {
    let host = &cfg.servers[0];
    let scheme = if host == "localhost" || host.starts_with("localhost:") {
        "http"
    } else {
        "https"
    };
    let u = if let Some(ref dom) = cfg.domain {
        format!("{}://{}/webnis/{}/{}", scheme, host, dom, map)
    } else {
        format!("{}://{}/webnis/{}", scheme, host, map)
    };
    let url = Url::parse_with_params(&u, &[(key, val)]).unwrap();
    url.as_str().parse::<hyper::Uri>().unwrap()
}

fn process2(ctx: Context, request: Request) -> impl Future<Item=String, Error=io::Error> {

    let (map, param) = match request.cmd {
        Cmd::GetPwNam => ("passwd", "name"),
        Cmd::GetPwUid => ("passwd", "uid"),
        Cmd::GetGrNam => ("group", "name"),
        Cmd::GetGrGid => ("group", "gid"),
        Cmd::GetGidList => ("gidlist", "name"),
    };
    let uri = build_uri(&ctx.inner.config, map, param, &request.args[0]);

    let https = HttpsConnector::new(4).unwrap();
    let client = Client::builder().build::<_, hyper::Body>(https);

    client.get(uri)
    //.map(|_| "hoi".to_string())
    //.map_err(|_| io::Error::new(io::ErrorKind::Other, "oh no!"))
    .map_err(|e| response_error(400, &format!("GET error: {}", e)))
    .and_then(|res| {
        // see if response is what we expected
        let is_json = res.headers().get("content-type").map(|h| h == "application/json").unwrap_or(false);
        if !is_json {
            if res.status().is_success() {
                future::err(response_error(416, "expected application/json"))
            } else {
                let code = res.status().as_u16() as i64;
                future::err(response_error(code, "HTTP error"))
            }
        } else {
            future::ok(res)
        }
    })
    .and_then(|res| {
        res
        .into_body()
        .concat2()
        .map_err(|_| response_error(400, "GET body error"))
    })
    .then(|res| {
        let body = match res {
            Ok(body) => body,
            Err(e) => return future::ok(e),
        };
        let data = match serde_json::from_slice::<Response>(&body) {
            Ok(resp) => resp.serialize(),
            Err(e) => response_error(400, e.description()),
        };
        future::ok(data)
    })
    //.map_err(|_: i32| io::Error::new(io::ErrorKind::Other, "oh no!"))
}

impl<'a> Request<'a> {
    fn parse(input: &'a str) -> Result<Request<'a>, String> {
        let mut parts = input.splitn(3, " ");
	    let c = match parts.next() {
		    None => return Err("NO".to_owned()),
            Some(c) => c,
        };
        let args = parts.collect::<Vec<_>>();
        let (cmd, nargs) = match c {
            //"auth" => (Cmd::Auth, 3),
            "getpwnam" => (Cmd::GetPwNam, 1),
            "getpwuid" => (Cmd::GetPwUid, 1),
            "getgrnam" => (Cmd::GetGrNam, 1),
            "getgrgid" => (Cmd::GetGrGid, 1),
            "getgidlist" => (Cmd::GetGidList, 1),
            _ => return Err(format!("unknown command {}", c)),
        };
        if nargs != args.len() {
            return Err(format!("{} needs {} arguments", c, nargs));
        }
        Ok(Request{ cmd: cmd, args: args })
    }
}

impl Response {
    fn serialize(&self) -> String {
        match serde_json::to_string(&*self) {
            Ok(v) => v,
            Err(_) => {
                r#"{ "error": { "code": 500, "message": "json::to_string error" } }"#.to_owned()
            }
        }
    }
}

fn response_error(code: i64, message: &str) -> String {
    serde_json::to_string(&Response::Error{
        error: ResponseError{
            code:       code,
            message:    message.to_owned(),
            data:       None,
        }
    }).unwrap()
}
