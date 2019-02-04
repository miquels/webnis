
use std::io;
use std::time::{Instant,Duration};
use std::sync::atomic::Ordering;

use url::percent_encoding::{
    utf8_percent_encode,
    DEFAULT_ENCODE_SET,
    QUERY_ENCODE_SET
};
use hyper;
use hyper::client::HttpConnector;
use hyper::{header,Method};
use hyper_tls::HttpsConnector;
use tokio::prelude::*;
use tokio::timer::Delay;
use futures::future;
use base64;

use crate::Context;
use crate::response::Response;

const MAX_TRIES: u32 = 8;
const RETRY_DELAY_MS: u64 = 250;
const REQUEST_TIMEOUT_MS: u64 = 1000;

/// Possible requests our clients can send us
pub(crate) struct Request<'a> {
    cmd:    Cmd,
    args:   Vec<&'a str>,
    arg0:   u32,
}

pub(crate) fn process(ctx: Context, line: String) -> Box<Future<Item=String, Error=io::Error> + Send> {
    let request = match Request::parse(&line) {
        Ok(req) => req,
        Err(e) => return Box::new(future::ok(Response::error(400, &e))),
    };

    // getpwuid() might be restricted to only looking up your own uid.
    if ctx.config.restrict_getpwuid && request.cmd == Cmd::GetPwUid {
        if ctx.uid > 0 && request.arg0 != ctx.uid {
            return Box::new(future::ok(Response::error(403, "Forbidden")));
        }
    }

    // getgrgid() might be restricted to only looking up gids < 1000 and your own gid.
    if ctx.config.restrict_getgrgid && request.cmd == Cmd::GetGrGid {
        if ctx.uid > 0 && request.arg0 >= 1000 && request.arg0 != ctx.gid {
            return Box::new(future::ok(Response::error(403, "Forbidden")));
        }
    }

    let anchor;
    let token = match ctx.config.http_authencoding.as_ref().map(|s| s.as_str()) {
        Some("base64") => {
            anchor = base64::encode(&ctx.config.http_authtoken);
            &anchor
        },
        _ => &ctx.config.http_authtoken,
    };
    let authorization = format!("{} {}", ctx.config.http_authschema, token);

    if request.cmd == Cmd::Auth {
        // authentication
        // note that the password has already been percent encoded by
        // the client (webnis-pam), we do not have to encode again.
        let path = format!("/{}/auth",
                        utf8_percent_encode(&ctx.config.domain, DEFAULT_ENCODE_SET));
        let mut body = format!("username={}&password={}",
                        utf8_percent_encode(&request.args[0], QUERY_ENCODE_SET),
                        request.args[1]);
        if request.args.len() > 2 {
            body.push_str(&format!("&service={}", utf8_percent_encode(&request.args[2], QUERY_ENCODE_SET)));
        }
        if request.args.len() > 3 {
            body.push_str(&format!("&remote={}", utf8_percent_encode(&request.args[3], QUERY_ENCODE_SET)));
        }
        return req_with_retries(&ctx, path, authorization, Some(body), 1)
    }

    if request.cmd == Cmd::Servers {
        // output the configured servers and the currently active server.
        let (active, seqno) = {
            let mut guard = ctx.http_client.lock().unwrap();
            let http_client = &mut *guard;
            let active = if http_client.client.is_none() {
                None
            } else {
                Some(&ctx.config.servers[http_client.seqno % ctx.config.servers.len()])
            };
            (active, http_client.seqno)
        };
        let reply = json!({
            "seqno":    seqno,
            "active":   active,
            "servers":  ctx.config.servers,
        });
        return Box::new(future::ok(format!("200 {}", reply.to_string())));
    }

    // map lookup
    let (map, param) = match request.cmd {
        Cmd::GetPwNam => ("passwd", "username"),
        Cmd::GetPwUid => ("passwd", "uid"),
        Cmd::GetGrNam => ("group", "group"),
        Cmd::GetGrGid => ("group", "gid"),
        Cmd::GetGidList => ("gidlist", "username"),
        _ => unreachable!(),
    };
    let path = format!("/{}/map/{}?{}={}&cred_uid={}",
                utf8_percent_encode(&ctx.config.domain, DEFAULT_ENCODE_SET),
                utf8_percent_encode(map, DEFAULT_ENCODE_SET),
                utf8_percent_encode(param, QUERY_ENCODE_SET),
                utf8_percent_encode(&request.args[0], QUERY_ENCODE_SET),
                ctx.uid);
    req_with_retries(&ctx, path, authorization, None, 0)
}

// build a hyper::Uri from a host and a path.
//
// host can be "hostname", "hostname:port", or "http(s)://hostname".
// if it's in the plain "hostname" format, the scheme will be http is
// the host is localhost, https otherwise.
fn build_uri(host: &str, path: &str) -> hyper::Uri {
    let url = if host.starts_with("http://") || host.starts_with("https://") {
        let host = host.trim_right_matches("/");
        format!("{}{}", host, path)
    } else if host == "localhost" || host.starts_with("localhost:") {
        format!("http://{}/.well-known/webnis{}", host, path)
    } else {
        format!("https://{}/.well-known/webnis{}", host, path)
    };
    url.parse::<hyper::Uri>().unwrap()
}

// build a new hyper::Client.
fn new_client(config: &crate::config::Config) -> hyper::Client<HttpsConnector<HttpConnector>> {
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
// On errors (except 404) we cycle to the next server.
//
// If there is a serious error from hyper::Client that we do not reckognize,
// we throw away the current hyper::Client instance and create a new one.
//
// This guards against bugs in hyper::Client or its dependencies
// that can get a hyper::Client stuck, see:
//
// https://github.com/hyperium/hyper/issues/1422
// https://github.com/rust-lang/rust/issues/47955
//
fn req_with_retries(ctx: &Context, path: String, authorization: String, body: Option<String>, try_no: u32) -> Box<Future<Item=String, Error=io::Error> + Send> {

    let ctx_clone = ctx.clone();

    let (client, seqno) = {
        let mut guard = ctx.http_client.lock().unwrap();
        let http_client = &mut *guard;
        if http_client.client.is_none() {
            // create a new http client.
            http_client.client.get_or_insert_with(|| new_client(&ctx.config));
            http_client.seqno += 1;
        }
        let cc = http_client.client.as_ref().unwrap().clone();
        (cc, http_client.seqno)
    };

    // build the uri based on the currently active webnis server.
    let server = &ctx.config.servers[seqno % ctx.config.servers.len()];
    let uri = build_uri(server, &path);
    let method = if body.is_some() { Method::POST } else { Method::GET };

    let mut builder = hyper::Request::builder();
    builder
        .uri(uri)
        .method(method)
        .header(header::AUTHORIZATION, authorization.as_str());
    if body.is_some() {
        builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    let request = builder
        .body(body.clone().map(|x| x.into()).unwrap_or(hyper::Body::empty()))
        .unwrap();

    let resp_body = client.request(request)
    .map_err(|e| {
        // something went very wrong. mark it with code 550 so that at the
        // end of the future chain we can detect it and retry.
        //
        // FIXME differ between real problems where we need to throw away the
        // hyper::Client and problems where we just need to switch to the next server.
        debug!("client: got error, need retry: {}", e);
        Response::error(550, &format!("GET error: {}", e))
    })
    .and_then(|res| {
        // see if response is what we expected
        let is_json = res.headers().get(header::CONTENT_TYPE).map(|h| h == "application/json").unwrap_or(false);
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
    });

    // add a timeout. need to have an answer in 1 second.
    let timeout = Duration::from_millis(REQUEST_TIMEOUT_MS);
    let body_tmout_wrapper = resp_body.timeout(timeout).map_err(|e| {
        debug!("got error {}", e);
        match e.into_inner() {
            Some(e) => e,
            None => Response::error(408, "request timeout"),
        }
    });

    let resp =
    body_tmout_wrapper.then(move |res| {
        let resp_body = match res {
            Ok(body) => body,
            Err(e) => {
                if !e.starts_with("401 ") &&
                   !e.starts_with("403 ") &&
                   !e.starts_with("404 ") &&
                   !ctx_clone.eof.load(Ordering::SeqCst) &&
                   try_no < MAX_TRIES {
                    {
    				    let mut guard = ctx_clone.http_client.lock().unwrap();
                        if (*guard).seqno == seqno {
                            // only do something if noone else took action.
                            debug!("invalidating server {} and scheduling retry {} because of {}",
                                   ctx_clone.config.servers[seqno % ctx_clone.config.servers.len()], try_no + 1, e);
                            if e.starts_with("550 ") {
                                // throw away hyper::Client
    				            (*guard).client.take();
                            } else {
                                // just switch to next server.
                                (*guard).seqno += 1;
                            }
                        } else {
                            debug!("scheduling try {} because of {}", try_no + 1, e);
                        }
                    }
					// and retry.
                    return req_with_retries(&ctx_clone, path, authorization, body, try_no + 1);
                } else {
                    return Box::new(future::ok(e));
                }
            },
        };
        Box::new(future::ok(Response::transform(resp_body)))
    });

    if try_no > 1 {
        let when = Instant::now() + Duration::from_millis(RETRY_DELAY_MS);
        Box::new(Delay::new(when).then(move |_| resp))
    } else {
        Box::new(resp)
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum Cmd {
    Auth,
    GetPwNam,
    GetPwUid,
    GetGrNam,
    GetGrGid,
    GetGidList,
    Servers,
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
    pub fn parse(input: &'a str) -> Result<Request<'a>, String> {
        let mut parts = input.splitn(5, " ");
        let mut buf = [0u8; 16];
	    let c = match parts.next() {
		    None => return Err("NO".to_owned()),
            Some(c) => tolower(c, &mut buf),
        };
        let args = parts.collect::<Vec<_>>();
        let (cmd, argsmin, argsmax) = match c {
            "auth" => (Cmd::Auth, 2, 4),
            "getpwnam" => (Cmd::GetPwNam, 1, 1),
            "getpwuid" => (Cmd::GetPwUid, 1, 1),
            "getgrnam" => (Cmd::GetGrNam, 1, 1),
            "getgrgid" => (Cmd::GetGrGid, 1, 1),
            "getgidlist" => (Cmd::GetGidList, 1, 1),
            "servers" => (Cmd::GetGidList, 0, 0),
            _ => return Err(format!("unknown command {}", c)),
        };
        if args.len() < argsmin || args.len() > argsmax {
            if argsmin == argsmax {
                return Err(format!("{} needs {} arguments", c, argsmin));
            } else {
                return Err(format!("{} needs {}-{} arguments", c, argsmin, argsmax));
            }
        }
        let arg0 = if cmd == Cmd::GetPwUid || cmd == Cmd::GetGrGid {
            match args[0].parse::<u32>() {
                Err(_) => return Err("Not a number".to_owned()),
                Ok(n) => n,
            }
        } else {
            0
        };
        Ok(Request{ cmd: cmd, args: args, arg0: arg0 })
    }
}

