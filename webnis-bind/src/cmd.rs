
use std::io;
use std::time::{Instant,Duration};

use url::Url;
use hyper;
use hyper::client::HttpConnector;
use hyper_tls::HttpsConnector;
use tokio::timer::Delay;
use futures::prelude::*;
use futures::future;

use super::Context;
use super::response::Response;

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

pub(crate) fn process(ctx: Context, line: String) -> Box<Future<Item=String, Error=io::Error> + Send> {
    let request = match Request::parse(&line) {
        Ok(req) => req,
        Err(e) => return Box::new(future::ok(Response::error(400, &e))),
    };

    let (map, param) = match request.cmd {
        Cmd::GetPwNam => ("passwd", "name"),
        Cmd::GetPwUid => ("passwd", "uid"),
        Cmd::GetGrNam => ("group", "name"),
        Cmd::GetGrGid => ("group", "gid"),
        Cmd::GetGidList => ("gidlist", "name"),
    };
    let uri = build_uri(&ctx.config, map, param, &request.args[0]);

    get_with_retries(&ctx, uri, 0)
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

// build a new hyper::Client.
fn new_client(config: &super::config::Config) -> hyper::Client<HttpsConnector<HttpConnector>> {
    let http2_only = config.http2_only.unwrap_or(false);
    let https = HttpsConnector::new(4).unwrap();
    hyper::Client::builder()
                .http2_only(http2_only)
                .keep_alive(true)
                .keep_alive_timeout(Duration::new(30, 0))
                .build::<_, hyper::Body>(https)
}

// This function can call itself recursively to keep on
// generating futures so as to retry.
//
// Here we do not just retry, but for every retry we invalidate the
// hyper::Client and instantiate a new one. This is needed to
// cycle between different webnis servers.
//
// It also guards against bugs in hyper::Client or its dependencies
// that can get a hyper::Client stuck, see:
//
// https://github.com/hyperium/hyper/issues/1422
// https://github.com/rust-lang/rust/issues/47955
//
fn get_with_retries(ctx: &Context, uri: hyper::Uri, n_retries: u32) -> Box<Future<Item=String, Error=io::Error> + Send> {

    let ctx_clone = ctx.clone();
    let uri_clone = uri.clone();

    let mut guard = ctx.client.lock().unwrap();
    let client = &*guard.get_or_insert_with(|| new_client(&ctx.config));

    let resp = client.get(uri)
    .map_err(|e| {
        // something went very wrong. mark it with code 550 so that at the
        // end of the future chain we can detect it and retry.
        debug!("client: got error, need retry: {}", e);
        Response::error(550, &format!("GET error: {}", e))
    })
    .and_then(|res| {
        // see if response is what we expected
        let is_json = res.headers().get("content-type").map(|h| h == "application/json").unwrap_or(false);
        if !is_json {
            if res.status().is_success() {
                future::err(Response::error(416, "expected application/json"))
            } else {
                let code = res.status().as_u16() as i64;
                future::err(Response::error(code, "HTTP error"))
            }
        } else {
            future::ok(res)
        }
    })
    .and_then(|res| {
        res
        .into_body()
        .concat2()
        .map_err(|_| Response::error(400, "GET body error"))
    })
    .then(move |res| {
        let body = match res {
            Ok(body) => body,
            Err(e) => {
                if e.starts_with("550 ") && n_retries < 8 {
                    debug!("scheduling retry {} because of {}", n_retries + 1, e);
					// invalidate current hyper::Client.
                    {
    				    let mut guard = ctx_clone.client.lock().unwrap();
    				    guard.take();
                    }
					// and retry.
                    return get_with_retries(&ctx_clone, uri_clone, n_retries + 1);
                } else {
                    return Box::new(future::ok(e));
                }
            },
        };
        Box::new(future::ok(Response::transform(body)))
    });

    if n_retries > 0 {
        debug!("n_retries > 1, delay and then retry");
        let when = Instant::now() + Duration::from_millis(250);
        Box::new(Delay::new(when).then(move |_| resp))
    } else {
        Box::new(resp)
    }
}

// over-engineered way to lowercase a string without allocating.
fn tolower<'a>(s: &'a str, buf: &'a mut [u8]) -> &'a str {
    let b = s.as_bytes();
    if b.len() > buf.len() {
        return s;
    }
    for idx in 0 .. b.len() {
        let c = b[idx];
        buf[idx] = if c >= 65 && c <= 90 { c + 32 } else { c };
    }
    match ::std::str::from_utf8(&buf[0..b.len()]) {
        Ok(s) => s,
        Err(_) => s,
    }
}

impl<'a> Request<'a> {
    fn parse(input: &'a str) -> Result<Request<'a>, String> {
        let mut parts = input.splitn(3, " ");
        let mut buf = [0u8; 16];
	    let c = match parts.next() {
		    None => return Err("NO".to_owned()),
            Some(c) => tolower(c, &mut buf),
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

