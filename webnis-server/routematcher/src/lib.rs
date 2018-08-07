//! # Route matcher.
//!
//! Simple route matcher for HTTP requests.
//! Uses the wellknown `:param`, `*splat` `(optional)` patterns that
//! are used by e.g. [Backbone Router](http://backbonejs.org/#Router).
//!
//! ```ignore
//! // Initialize the matcher.
//! let builder = Builder::new();
//! builder
//!     .add("/user/:id")
//!     .label("user");
//! let matcher = builder.compile();
//!
//! let m = match matcher.match_req(&request) {
//!     None => { ... 404 not found ... },
//!     Some(m) => m,
//! };
//! match m.label() {
//!     Some("posts") => {
//!         let post_id = m.route_param("id");
//!         let arg = m.query_param("foo");
//!         // ....
//!     },
//! }
//! ```
//!
#[macro_use] extern crate lazy_static;
extern crate regex;
extern crate http;
extern crate serde_json;

use std::io;
use std::collections::HashMap;
use std::cell::RefCell;
use std::iter::FromIterator;

use regex::{RegexSet,Regex,Captures};
use http::{header,Method,Request,Response,StatusCode};

/// A Matcher stores all the route-patterns that we can match on.
/// ```ignore
/// let builder = Builder::new();
/// builder
///     .add("/user/:id")
///     .method(&Method::GET)
///     .method(&Method::POST)
///     .label("user");
/// builder
///     .add("/posts/p:id")
///     .label("post");
/// let matcher = builder.compile();
/// ```
#[derive(Debug)]
pub struct Matcher {
    routes_pat:         Vec<String>,
    routes_re:          Vec<Regex>,
    set:                Option<RegexSet>,
    methods:            HashMap<usize, Vec<Method>>,
    labels:             HashMap<usize, String>,
    encoded_slashes_ok: bool,
}

#[derive(Debug)]
pub struct Builder {
    inner:              RefCell<Matcher>,
}

#[derive(Debug,Default)]
struct MatchState {
    decoded_path:   String,
    decoded_query:  Option<String>,
    query_offsets:  Option<Vec<(usize, usize, usize)>>,
    route_index:    usize,
    body_params:    Option<HashMap<Vec<u8>, Vec<u8>>>,
}

fn has_body<T>(req: &Request<T>) -> bool {
    req.headers().contains_key("content-length") ||
    req.headers().contains_key("transfer-encoding")
}

impl Builder {

    /// Create a new Builder.
    pub fn new() -> Builder {
        let m = Matcher{
                routes_pat:         Vec::new(),
                routes_re:          Vec::new(),
                set:                None,
                labels:             HashMap::new(),
                methods:            HashMap::new(),
                encoded_slashes_ok: false,
        };
        Builder{ inner: RefCell::new(m) }
    }

    /// Add a route to a matcher.
    pub fn add(&self, s: impl AsRef<str>) -> &Self {
        let mut inner = self.inner.borrow_mut();
        inner.routes_pat.push(build_matcher_re(s.as_ref()));
        self
    }

    /// Add a label.
    pub fn label(&self, label: impl AsRef<str>) -> &Self {
        let mut inner = self.inner.borrow_mut();
        if inner.routes_pat.len() == 0 {
            panic!("Matcher::label: cannot set on empty route");
        }
        let idx = inner.routes_pat.len() - 1;
        inner.labels.insert(idx, label.as_ref().to_owned());
        self
    }

    /// Method of the request must match
    pub fn method(&self, method: &Method) -> &Self {
        let mut inner = self.inner.borrow_mut();
        if inner.routes_pat.len() == 0 {
            panic!("Matcher::method: cannot set on empty route");
        }
        let idx = inner.routes_pat.len() - 1;
        if inner.methods.get(&idx).is_none() {
            inner.methods.insert(idx, Vec::new());
        }
        let v = inner.methods.get_mut(&idx).unwrap();
        v.push(method.to_owned());
        self
    }

    /// Compile the route patterns into regexps.
    pub fn compile(self) -> Matcher {
        let mut this = self.inner.into_inner();
        {
            let re_s = this.routes_pat.iter().map(|r| Regex::new(r).unwrap());
            this.routes_re.extend(re_s);;
            this.set = Some(RegexSet::new(&this.routes_pat).unwrap());
        }
        this
    }
}

impl Matcher {
    /// Preflight check: see if request is sane and match our routes. Stores
    /// the state it builds internally in the request, so that_req later
    /// on does not have to do the same work again.
    ///
    /// Can return status codes:
    /// ```
    /// StatusCode::BAD_REQUEST         could not find/decode path in request
    /// StatusCode::NOT_FOUND           no match found
    /// StatusCode::METHOD_NOT_ALLOWED  match found, but not for request method.
    /// ```
    pub fn preflight<T>(&self, req: &mut Request<T>) -> Result<(), StatusCode> {

        if req.extensions().get::<MatchState>().is_some() {
            return Ok(());
        }
        let mut state = MatchState::default();

        // decode path and store it in the request.
        let path = match percent_decode_utf8(req.uri().path()) {
            (Some(path), slash) => {
                if slash && !self.encoded_slashes_ok {
                    return Err(StatusCode::BAD_REQUEST);
                }
                path
            },
            (None, _) => return Err(StatusCode::BAD_REQUEST),
        };
        state.decoded_path = path;

        // Some extra test in case this is a POST, so we can rely on the fact
        // that the request has a valid body later on.
        if req.method() == &Method::POST {
            if !has_body(&req) {
                return Err(StatusCode::LENGTH_REQUIRED);
            }
            let type_ok = match req.headers().get("content-type") {
                Some(h) => h.to_str().unwrap_or("").contains("application/x-www-form-urlencoded") ||
                           h.to_str().unwrap_or("").contains("application/json"),
                None => false,
            };
            if !type_ok {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
        }

        // Now decode the query. If we needed to allocate a fresh buffer
        // because of percent-encoding, store that buffer in the request.
        let (query_offsets, buffer) = decode_query_get_offsets(req.uri().query());
        state.decoded_query = buffer;
        state.query_offsets = query_offsets;

        // get a list of matching routes.
        let matched = self.set.as_ref().unwrap().matches(&state.decoded_path);

        let mut n = None;
        let mut status = StatusCode::NOT_FOUND;
        // NLL ident.
        {
            // now find the first route that matches the method.
            let reqm = req.method();
            let methods = &self.methods;
            for idx in matched.into_iter() {
                match methods.get(&idx) {
                    None => {
                        n = Some(idx);
                        break;
                    },
                    Some(mlist) => {
                        if mlist.iter().find(|m| m == reqm).is_some() {
                            n = Some(idx);
                            break;
                        }
                        status = StatusCode::METHOD_NOT_ALLOWED;
                    },
                }
            }
        }

        // on no match return with an error.
        let n = match n {
            None => return Err(status),
            Some(n) => n,
        };


        state.route_index = n;
        req.extensions_mut().insert(state);
        Ok(())
    }

    /// Match a request and return the match. Errors can be:
    /// ```
    /// StatusCode::BAD_REQUEST         could not find/decode path in request
    /// StatusCode::NOT_FOUND           no match found
    /// StatusCode::METHOD_NOT_ALLOWED  match found, but not for request method.
    /// ```
    pub fn match_req<'a, 'b: 'a, T>(&'a self, req: &'b mut Request<T>) -> Result<Match<'a>, StatusCode> {

        self.preflight(req)?;
        let state = req.extensions().get::<MatchState>().unwrap();
        let n = state.route_index;

        // pattern "n" matches. Run regexp "n" and return result.
        if let Some(caps) = self.routes_re[n].captures(&state.decoded_path) {
            let label = self.labels.get(&n).as_ref().map(|s| s.as_str());
            return Ok(Match{
                caps: caps,
                idx: n,
                label: label,
                query_params: map_query_params(req, state.query_offsets.as_ref()),
                body_params: state.body_params.as_ref(),
            });
        }

        // never reached.
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// This is like preflight(), but it returns a Response on error. Makes it
    /// easy to quickly return errors on no match, for example:
    /// ```no_run
    /// if let Err(resp) = matcher.preflight_resp(req) {
    ///     return Box::new(future::ok(resp));
    /// }
    /// ```      
    pub fn preflight_resp<T>(&self, req: &mut Request<T>) -> Result<(), Response<T>>
        where T: std::convert::From<String> {

        let body_maybe = has_body(&req) ||
            req.method() == &Method::PUT ||
            req.method() == &Method::POST;

        let status = match self.preflight(req) {
            Ok(r) => return Ok(r),
            Err(status) => status,
        };

        let mut bldr = Response::builder();
        if body_maybe {
               // it contains a body but we haven't read it- and aren't going
               // to, so tell hyper to close the current connection.
               bldr.header(header::CONNECTION, "close");
        }
        let msg = status.canonical_reason().unwrap_or(status.as_str()).to_string();
        bldr
            .header(header::CONTENT_TYPE, "text/plain")
            .status(status);
        Err(bldr.body(msg.into()).unwrap())
    }

    /// This is like match_req(), but it returns a Response on error. Makes it
    /// easy to quickly return errors on no match, for example:
    /// ```no_run
    /// let m = match matcher.match_req_resp(req) {
    ///     Ok(m) => m,
    ///     Err(resp) => {
    ///         return Box::new(future::ok(resp));
    ///     }
    /// };
    /// ```      
    pub fn match_req_resp<'a, 'b: 'a, T>(&'a self, req: &'b mut Request<T>) -> Result<Match<'a>, Response<T>>
        where T: std::convert::From<String> {

        if let Err(resp) = self.preflight_resp(req) {
            return Err(resp);
        }

        let status = match self.match_req(req) {
            Ok(r) => return Ok(r),
            Err(status) => status,
        };

        let mut bldr = Response::builder();
        let msg = status.canonical_reason().unwrap_or(status.as_str()).to_string();

        Err(bldr
            .header(header::CONTENT_TYPE, "text/plain")
            .status(status)
            .body(msg.into()).unwrap())
    }

    pub fn parse_body<T>(&self, req: &mut Request<T>, data: &[u8]) -> Result<(), io::Error> {
        #[derive(PartialEq)]
        enum CT {
            Form,
            Json,
            NotFound,
        };
        let ct = match req.headers().get("content-type") {
            None => CT::NotFound,
            Some(ct) => {
                let s = ct.to_str().unwrap_or("");
                if s.contains("application/x-www-form-urlencoded") {
                    CT::Form
                }
                else if s.contains("application/json") {
                    CT::Json
                }
                else {
                    CT::NotFound
                }
            },
        };
        let state = req.extensions_mut().get_mut::<MatchState>().unwrap();
        match ct {
            CT::Form => {
                let mut hm : HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
                let data = percent_decode(data);
                data.split(|&b| b == b'&').for_each(|kv| {
                    let mut x = kv.splitn(2, |&b| b == b'=');
                    hm.insert(x.next().unwrap().to_vec(), x.next().unwrap_or(b"").to_vec());
				});
				state.body_params = Some(hm);
                return Ok(());
			},
            CT::Json => {
                let v : HashMap<String, String> = serde_json::from_slice(data)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "json deserialization fail"))?;
                let b_iter = v.into_iter().map(|(k, v)| (k.into_bytes(), v.into_bytes()));
                let hm : HashMap<_,_> = HashMap::from_iter(b_iter);
				state.body_params = Some(hm);
                return Ok(());
            },
            _ => {},
        }

        Err(io::Error::new(io::ErrorKind::Other, "body contents fail"))
    }
}

/// This struct is returned when a path matches a route.
///
/// For example, on path `/posts/p10?arg=foo`:
/// ```ignore
/// let m = match matcher.request(&request) {
///     None => { ... 404 not found ... },
///     Some(m) => m,
/// };
/// match m.label().unwrap_or("") {
///     "posts" => {
///         let post_id = m.route_param("id");
///         let arg = m.query_param("foo");
///         ....
///     },
///     "user" => {
///         let user_id = m.route_param("id");
///         ....
///     },
///     _ => {
///         ....
///     },
/// }
/// ```
#[derive(Debug)]
pub struct Match<'a> {
    idx:            usize,
    label:          Option<&'a str>,
    caps:           Captures<'a>,
    query_params:   Option<HashMap<&'a str, &'a str>>,
    body_params:    Option<&'a HashMap<Vec<u8>, Vec<u8>>>,
}

impl<'a> Match<'a> {
    /// The percent-decoded path that was matched.
    pub fn path(&self) -> &'a str {
        self.caps.get(0).map_or("", |m| m.as_str())
    }

    /// Look up a named route parameter.
    pub fn route_param(&self, s: &str) -> Option<&'a str> {
        match self.caps.name(s) {
            Some(n) => Some(n.as_str()),
            None => None,
        }
    }

    /// Look up a query parameter.
    pub fn query_param(&self, s: &str) -> Option<&'a str> {
        if let Some(ref m) = self.query_params {
            if let Some(r) = m.get(s) {
                let r :&str = *r;
                return Some(r);
            }
        }
        None
    }

    /// Look up a body parameter.
    pub fn body_param(&self, s: &str) -> Option<&'a str> {
        if let Some(ref m) = self.body_params {
            if let Some(r) = m.get(s.as_bytes()) {
                return std::str::from_utf8(r).ok();
            }
        }
        None
    }

    /// Look up a body parameter. Body parameters in the application/x-www-form-urlencoded
    /// encoding are binary, and do not have to be an utf-8 string. Return a &[u8].
    pub fn body_param_bytes(&self, s: &str) -> Option<&'a [u8]> {
        if let Some(ref m) = self.body_params {
            if let Some(r) = m.get(s.as_bytes()) {
                return Some(r);
            }
        }
        None
    }

    /// Return the label (if any) of the route that was matched.
    pub fn label(&self) -> Option<&'a str> {
        self.label
    }
}

// Turn a route-matcher expression into a regular expression.
fn build_matcher_re(matcher: &str) -> String {

    // first pre-escape a few special characters that we map to
    // part of the regexp later on, so that they do not get
    // mangled by the regex::escape below.
    let s = matcher.chars().map(|c|
        match c {
            '*' => '\u{1}',
            '(' => '\u{2}',
            ')' => '\u{3}',
            o => o,
        }).collect::<String>();
    let s = regex::escape(&s);
    
    // make (whatever) optional
    lazy_static! {
        static ref RE1: Regex = Regex::new(r"\u{2}([^\u{2}\u{3}]*)\u{3}").unwrap();
    }
    let s = RE1.replace_all(&s, r"($1)?");
    //println!("re1: {}", s);
    
    // handle :label
    lazy_static! {
        static ref RE2: Regex = Regex::new(r":([-_0-9a-zA-Z]+)").unwrap();
    }
    let s = RE2.replace_all(&s, r"(?P<$1>[^/]+)");
    //println!("re2: {}", s);

    // then :splat
    lazy_static! {
        static ref RE3: Regex = Regex::new(r"\u{1}([-_0-9a-zA-Z]+)").unwrap();
    }
    let s = RE3.replace_all(&s, r"(?P<$1>.*)");
    //println!("re3: {}", s);
    
    format!("^{}$", s)
}

// Internal percent-decoder.
#[derive(Clone, Debug)]
struct PercentDecoder<'a> {
    bytes: 		std::slice::Iter<'a, u8>,
}

impl<'a> PercentDecoder<'a> {
    #[inline]
    fn new(input: &'a str) -> PercentDecoder<'a> {
        PercentDecoder {
            bytes: input.as_bytes().iter(),
        }
    }
    #[inline]
    fn from_bytes(input: &'a [u8]) -> PercentDecoder<'a> {
        PercentDecoder {
            bytes: input.iter(),
        }
    }
}

// iterator helper.
fn after_percent_sign(iter: &mut std::slice::Iter<u8>) -> Option<u8> {
    let initial_iter = iter.clone();
    let h = iter.next().and_then(|&b| (b as char).to_digit(16));
    let l = iter.next().and_then(|&b| (b as char).to_digit(16));
    if let (Some(h), Some(l)) = (h, l) {
        Some(h as u8 * 0x10 + l as u8)
    } else {
        *iter = initial_iter;
        None
    }
}

// This iterator is slightly different from the one
// in the percent_enconfig crate. Instead of one byte, it returns
// a (u8, u8) tuple. The members of the tuple are:
//
// - u8:  next byte from the stream
// - u8:  next decoded byte from the stream
//
impl<'a> Iterator for PercentDecoder<'a> {
    type Item = (u8, u8);

    fn next(&mut self) -> Option<(u8, u8)> {
        self.bytes.next().map(|&byte| {
            if byte == b'%' {
                match after_percent_sign(&mut self.bytes) {
					Some(c) => (byte, c),
					None => (byte, byte),
				}
            } else {
                (byte, byte)
            }
        })
    }
}

// is this slice valid utf8?
fn ok_utf8(bufp: Option<&Vec<u8>>, start: usize, end: usize) -> bool {
    match bufp {
        None => true,
        Some(bufp) => std::str::from_utf8(&bufp[start..end]).is_ok(),
    }
}

// Decode a percent-encoded string and make sure it's valid utf-8.
// While decoding, check if there are percent-encoded slashes
// present in any path-segment.
fn percent_decode_utf8(s: &str) -> (Option<String>, bool) {
    let n = s.as_bytes().iter().filter(|&&c| c == b'%').count();
    let c = if s.len() > 2*n { s.len() - 2*n } else { 8 };
    let mut v = Vec::with_capacity(c);
    let mut encoded_slash = false;

    let iterator = PercentDecoder::new(s);
    for (orig, byte) in iterator {
        if orig != b'/' && byte == b'/' {
            encoded_slash = true;
        }
        v.push(byte);
    }

    (String::from_utf8(v).ok(), encoded_slash)
}

// Decode a percent-encoded &[u8] into bytes.
fn percent_decode(s: &[u8]) -> Vec<u8> {
    let n = s.iter().filter(|&&c| c == b'%').count();
    let c = if s.len() > 2*n { s.len() - 2*n } else { 8 };
    let mut v = Vec::with_capacity(c);

    let iterator = PercentDecoder::from_bytes(s);
    for (_, byte) in iterator {
        v.push(byte);
    }

    v
}

// Walk over the query string, percent-decoding as we go. Remember the
// offsets into the query string of equal-signs '=' and
// query-param-seperators '&'.
//
// Returns a Vec of tuples of those offsets.
//
// If percent-decoding was needed, also return the buffer that the
// query string was decoded into.
fn decode_query_get_offsets(s: Option<&str>) -> (Option<Vec<(usize, usize, usize)>>, Option<String>) {

    // Return if the query is None.
    let s = match s {
        Some(s) => s,
        None => return (None, None),
    };

    // See if any percent signs are present- if so, allocate a buffer to decode into.
    let n = s.as_bytes().iter().filter(|&&c| c == b'%').count();
    let mut bufp = if n > 0 {
        let c = if s.len() > 2*n { s.len() - 2*n } else { 8 };
        Some(Vec::with_capacity(c))
    } else {
        None
    };

    // State.
    let mut start_pos = 0;
    let mut equal_pos = 0;
    let mut pos = 0;

    let mut offsets = Vec::new();

    let mut iterator = PercentDecoder::new(s);
    loop {
        // decode next byte.
        let (o_byte, d_byte) = match iterator.next() {
            None => {
                // we're done, finish up.
                if pos > start_pos && ok_utf8(bufp.as_ref(), start_pos, pos) {
                    if equal_pos == start_pos {
                        equal_pos = pos;
                    }
                    offsets.push((start_pos, equal_pos, pos));
                }
                break;
            },
            Some((o, b)) => (o, b),
        };

        // save into the buffer if we're decoding.
        if let Some(ref mut b) = bufp {
            b.push(d_byte);
        }

        // "state machine"
        match o_byte {
            b'=' => {
                equal_pos = pos;
                pos += 1;
            },
            b'&' => {
                // start of next param, finalize current one.
                if pos > start_pos && ok_utf8(bufp.as_ref(), start_pos, pos) {
                    if equal_pos == start_pos {
                        equal_pos = pos;
                    }
                    offsets.push((start_pos, equal_pos, pos));
                    pos += 1;
                } else {
                    // We did not want this data, so skip it.
                    if let Some(ref mut b) = bufp {
                        // If we have a mutable buffer delete it.
                        b.truncate(start_pos);
                        pos = start_pos;
                    } else {
                        pos += 1;
                    }
                }
                start_pos = pos;
                equal_pos = pos;
            }
            _ => pos += 1,
        }
    }

    // Turn optional Vec<u8> into optional String.
    let bufp = bufp.map(|b| unsafe { String::from_utf8_unchecked(b) });

    (Some(offsets), bufp)
}

// Lookup the (perhaps decoded) query string, and build a hashmap of
// key/value parameters based on the offsets.
fn map_query_params<'a, T>(req: &'a Request<T>, offsets: Option<&Vec<(usize, usize, usize)>>) -> Option<HashMap<&'a str, &'a str>> {

    // If offsets is None, return now.
    let offsets = offsets?;

    // If we decoded the query string into a buffer, use the buffer,
    // otherwise use the plain query string from the request.
    let q = match req.extensions().get::<MatchState>() {
        Some(state) if state.decoded_query.is_some() => state.decoded_query.as_ref().unwrap(),
        _ => req.uri().query().unwrap(),
    };

    // Create the hashmap.
    let mut map = HashMap::new();
    for &(start, equal, end) in offsets {
        let key = &q[start..equal];
        let val = if end > equal + 1 { &q[equal+1..end] } else { "" };
        map.insert(key, val);
    }
    Some(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percent_decode() {
        let s = "hallo%20daar";
        let d = percent_decode_utf8(s);
        let expected = (Some("hallo daar".to_string()), false);
        assert_eq!(d, expected);
    }

    #[test]
    fn test_match() {
        let mut request = Request::builder()
            .uri("http://localhost/user/mike?foo=bar")
            .method("POST")
            .body(())
            .unwrap();

        let builder = Builder::new();
        builder.add("/user/:id").label("user").method(&Method::POST).method(&Method::GET);
        let matcher = builder.compile();

        let m = matcher.match_req(&mut request);
        assert!(m.is_some());

        let m = m.unwrap();
        assert_eq!(m.label, Some("user"));
        assert_eq!(m.route_param("id"), Some("mike"));
        assert_eq!(m.route_param("whatever"), None);
        assert_eq!(m.query_param("foo"), Some("bar"));
        assert_eq!(m.query_param("whatever"), None);
        assert_eq!(m.path(), "/user/mike");
    }
}

