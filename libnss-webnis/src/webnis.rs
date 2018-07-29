
use std::time::Duration;
use std::os::unix::net::UnixStream;
use std::io::{BufRead,BufReader};
use std::thread::sleep;
use std::io::Write;

use super::nss::{Passwd,Group,uid_t,gid_t,NssResult,NssError};

static SOCKADDR: &'static str = "webnis-bind.sock";

pub struct Webnis;

impl Webnis {
    pub fn new() -> Webnis {
        if log_enabled!(::log::Level::Debug) {
            ::env_logger::init();
        }
        Webnis
    }

    pub fn getgidlist(&self, name: &str) -> NssResult<(Vec<gid_t>)> {
        let reply = wnbind_get("getgidlist", name)?;
        decode_gidlist(reply)
    }

    pub fn getgrnam(&self, grp: Group, name: &str) -> NssResult<()> {
        let reply = wnbind_get("getgrnam", name)?;
        decode_group(grp, reply)
    }

    pub fn getgrgid(&self, grp: Group, gid: gid_t) -> NssResult<()> {
        let reply = wnbind_get("getgrgid", &gid.to_string())?;
        decode_group(grp, reply)
    }

    pub fn getpwnam(&self, pwd: Passwd, name: &str) -> NssResult<()> {
        let reply = wnbind_get("getpwnam", name)?;
        decode_passwd(pwd, reply)
    }

    pub fn getpwuid(&self, pwd: Passwd, uid: uid_t) -> NssResult<()> {
        let reply = wnbind_get("getpwuid", &uid.to_string())?;
        decode_passwd(pwd, reply)
    }
}

// open socket, send one command, read reply, return.
fn wnbind_try(cmd: &str, arg: &str) -> NssResult<String> {

    // connect to webnis-bind.
    let mut socket = match UnixStream::connect(SOCKADDR) {
        Ok(s) => s,
        Err(e) => {
            debug!("connect to {}: {}", SOCKADDR, e);
            return Err(e)?;
        },
    };
    socket.set_read_timeout(Some(Duration::new(3, 0))).ok();
    socket.set_write_timeout(Some(Duration::new(1, 0))).ok();

    // send request.
    let b = format!("{} {}\n", cmd, arg).into_bytes();
    if let Err(e) = socket.write_all(&b) {
        debug!("write to {}: {}", SOCKADDR, e);
        return Err(e)?;
    }

    // get reply.
    let mut line = String::new();
    let mut rdr = BufReader::new(socket);
    if let Err(e) = rdr.read_line(&mut line) {
        debug!("reading from {}: {}", SOCKADDR, e);
        return Err(e)?;
    }

    // Now decode the line.
    let mut s = line.splitn(2, ' ');
    let num = s.next().unwrap();
    let val = s.next().unwrap_or("");

    let code = match num.parse::<u16>() {
        Ok(c) => c,
        Err(_) => {
            debug!("error: got garbage answer [{}]", num);
            return Err(NssError::Unavailable);
        },
    };

    match code {
        200 ... 299 => {
            Ok(val.to_string())
        },
        404 => Err(NssError::NotFound),
        400 ... 499 => {
            debug!("error: {}", line);
            Err(NssError::TryAgain)
        },
        _ => {
            debug!("error: {}", line);
            Err(NssError::Unavailable)
        }
    }
}

// call cmd_run and sleep/retry a few times if we fail.
fn wnbind_get(cmd: &str, arg: &str) -> NssResult<String> {
    let max_tries = 3;
    for tries in 0 .. max_tries {
        match wnbind_try(cmd, arg) {
            Ok(r) => {
                if r.contains(0 as char) {
                    debug!("wnbind answer contains a literal 0");
                    return Err(NssError::Unavailable);
                }
                return Ok(r);
            },
            res @ Err(NssError::NotFound) => return res,
            Err(NssError::TimedOut) => {},
            _ => {
                if tries < max_tries - 1 {
                    sleep(Duration::new(3, 0));
                }
            },
        }
    }
    Err(NssError::Unavailable)
}

// decode passwd line
fn decode_passwd(mut pwd: Passwd, line: String) -> NssResult<()> {

    // let's be anal about this.
    let fields : Vec<&str> = line.split(':').collect();
    if fields.len() != 7 {
        debug!("wrong number of fields for passwd, expected 7, got {}", fields.len());
        return Err(NssError::Unavailable);
    }
    if fields[0].len() == 0 {
        debug!("wnbind reply contains empty username field");
        return Err(NssError::Unavailable);
    }
    let uid = match fields[2].parse::<uid_t>() {
        Ok(n) => n,
        Err(_) => {
            debug!("invalid pw_uid in answer: {}", fields[2]);
            return Err(NssError::Unavailable);
        },
    };
    let gid = match fields[3].parse::<gid_t>() {
        Ok(n) => n,
        Err(_) => {
            debug!("invalid pw_gid in answer: {}", fields[3]);
            return Err(NssError::Unavailable);
        },
    };
    pwd.set_name(fields[0]);
    pwd.set_passwd(fields[1]);
    pwd.set_uid(uid);
    pwd.set_gid(gid);
    pwd.set_gecos(fields[4]);
    pwd.set_home(fields[5]);
    pwd.set_shell(fields[6]);

    pwd.result()
}

// decode group line
fn decode_group(mut grp: Group, line: String) -> NssResult<()> {

    // let's be anal about this.
    let fields : Vec<&str> = line.split(':').collect();
    if fields.len() != 4 {
        debug!("wrong number of fields for group, expected 4, got {}", fields.len());
        return Err(NssError::Unavailable);
    }
    if fields[0].len() == 0 {
        debug!("wnbind reply contains empty groupname field");
        return Err(NssError::Unavailable);
    }
    let gid = match fields[2].parse::<gid_t>() {
        Ok(n) => n,
        Err(_) => {
            debug!("invalid gr_gid in answer: {}", fields[2]);
            return Err(NssError::Unavailable);
        },
    };
    grp.set_name(fields[0]);
    grp.set_passwd(fields[1]);
    grp.set_gid(gid);
    let members : Vec<&str> = fields[3].split(',').collect();
    grp.set_members(members);

    grp.result()
}

// decode gidlist line
fn decode_gidlist(line: String) -> NssResult<Vec<gid_t>> {

    // let's be anal about this.
    let fields : Vec<&str> = line.split(':').collect();
    if fields.len() != 2 {
        debug!("wrong number of fields for gidlist, expected 2, got {}", fields.len());
        return Err(NssError::Unavailable);
    }
    let mut gids = Vec::new();
    for gid in fields[1].split(',') {
        let g = match gid.parse::<gid_t>() {
            Ok(n) => n,
            Err(_) => {
                debug!("invalid gid in answer: {}", gid);
                return Err(NssError::Unavailable);
            }
        };
        gids.push(g);
    }
    Ok(gids)
}

