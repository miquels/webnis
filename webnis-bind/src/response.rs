use std::error::Error;

use serde_json;
use hyper;
use libc::{uid_t,gid_t};

#[derive(Serialize,Deserialize)]
#[serde(untagged)]
pub enum Response<'a> {
    Success { #[serde(borrow)] result: ResponseVariants<'a> },
    Error { error: ResponseError },
}

#[derive(Serialize,Deserialize)]
pub struct ResponseError {
    code:       i64,
    message:    String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data:       Option<String>,
}

#[derive(Serialize,Deserialize)]
#[serde(untagged)]
pub enum ResponseVariants<'a> {
	Passwd(#[serde(borrow)] Passwd<'a>),
	Group(#[serde(borrow)] Group<'a>),
	Gidlist(#[serde(borrow)] Gidlist<'a>),
	Auth(Auth),
}

#[derive(Serialize,Deserialize)]
pub struct Passwd<'a> {
    username:   &'a str,
    passwd:     &'a str,
    uid:        uid_t,
    gid:        gid_t,
    gecos:      &'a str,
    home:       &'a str,
    shell:      &'a str,
}

#[derive(Serialize,Deserialize)]
pub struct Group<'a> {
    group:      &'a str,
    passwd:     &'a str,
    gid:        gid_t,
    members:    Vec<&'a str>,
}

#[derive(Serialize,Deserialize)]
pub struct Gidlist<'a> {
    username:   &'a str,
    gidlist:    Vec<gid_t>,
}

#[derive(Serialize,Deserialize)]
pub struct Auth {}

impl<'a> Response<'a> {

    pub fn transform(s: hyper::Chunk) -> String {
        let data = match serde_json::from_slice::<Response>(&s) {
            Ok(resp) => resp,
            Err(e) => return Response::error(400, e.description()),
        };
        let result = match data {
            Response::Success{ result } => result,
            Response::Error{ error } => return Response::error(error.code, &error.message),
        };
        let line = match result {
            ResponseVariants::Passwd(p) => p.to_line(),
            ResponseVariants::Group(p) => p.to_line(),
            ResponseVariants::Gidlist(p) => p.to_line(),
            ResponseVariants::Auth(p) => p.to_line(),
        };
        line
    }

    #[allow(unused)]
    pub fn serialize(&self) -> String {
        match serde_json::to_string(&*self) {
            Ok(v) => v,
            Err(_) => {
                r#"{ "error": { "code": 500, "message": "json::to_string error" } }"#.to_owned()
            }
        }
    }

    #[allow(unused)]
    pub fn json_error(code: i64, message: &str) -> String {
        serde_json::to_string(&Response::Error{
            error: ResponseError{
                code:       code,
                message:    message.to_owned(),
                data:       None,
            }
        }).unwrap()
    }

    pub fn error(code: i64, message: &str) -> String {
        format!("{} {}", code, message)
    }
}

impl<'a> Passwd<'a> {
    pub fn to_line(&self) -> String {
        format!("200 {}:{}:{}:{}:{}:{}:{}", self.username, self.passwd, self.uid, self.gid, self.gecos, self.home, self.shell)
    }
}

impl<'a> Group<'a> {
    pub fn to_line(&self) -> String {
        let members = self.members.join(",");
        format!("200 {}:{}:{}:{}", self.group, self.passwd, self.gid, members)
    }
}

impl<'a> Gidlist<'a> {
    pub fn to_line(&self) -> String {
        let gid_array = self.gidlist.iter().map(|m| m.to_string()).collect::<Vec<String>>();
        let gids = gid_array.iter().map(|s| s.as_str()).collect::<Vec<&str>>().join(",");
        format!("200 {}:{}", self.username, gids)
    }
}

impl Auth {
    pub fn to_line(&self) -> String {
        "200 OK".to_string()
    }
}

