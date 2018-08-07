use std;
use std::time::Duration;
use std::os::unix::net::UnixStream;
use std::io::{BufRead,BufReader};
use std::thread::sleep;
use std::io::Write;

use percent_encoding::{
    percent_encode,
    QUERY_ENCODE_SET
};

use pamsm::{self,PamServiceModule,PamError};

static SOCKADDR: &'static str = "/var/run/webnis-bind.sock";

const MAX_TRIES: u32 = 2;
const RETRY_DELAY_MS: u64 = 2500;
const REQUEST_READ_TIMEOUT_MS: u64 = 2500;
const REQUEST_WRITE_TIMEOUT_MS: u64 = 1000;

// lazy static so that a first call of DEBUG() initialises the debug logger.
lazy_static! {
    static ref DEBUG: fn() -> () = {
        if log_enabled!(::log::Level::Debug) {
            ::env_logger::init();
        }
		|| {}
    };
}

// the arguments that can be passed in the /etc/pam.d/FILE config file.
#[allow(non_camel_case_types)]
enum PamArgs {
    // enable debugging
    DEBUG           = 1,
    // unused, use_first_pass is the default.
    USE_FIRST_PASS  = 2,
}

impl PamArgs {
    fn parse(args: &Vec<String>) -> u32 {
        let mut a = 0u32;
        for i in args.iter() {
            match i.as_str() {
                "debug"             => a |= PamArgs::DEBUG as u32,
                "use_first_pass"    => a |= PamArgs::USE_FIRST_PASS as u32,
                _ => {},
            }
        }
        a
    }
}

// type to impl the PamServiceModule on.
pub struct Webnis;

impl PamServiceModule for Webnis {
    fn authenticate(self: &Self, pam: pamsm::Pam, _pam_flags: pamsm::PamFlag, args: Vec<String>) -> PamError {

        // config file cmdline args.
        let pam_args = PamArgs::parse(&args);
        if (pam_args & PamArgs::DEBUG as u32) != 0 {
            DEBUG();
        }

        let user = match pam.get_user(None) {
            Ok(Some(u)) => u,
            Ok(None) => return PamError::USER_UNKNOWN,
            Err(e) => return e,
        };

        let pass = match pam.get_authtok(None) {
            Ok(Some(p)) => p,
            Ok(None) => return PamError::AUTH_ERR,
            Err(e) => return e,
        };
        let pass : String = percent_encode(&pass, QUERY_ENCODE_SET).collect();

        // run authentication.
        match wnbind_auth(user, &pass) {
            Ok(_) => PamError::SUCCESS,
            Err(e) => e,
        }
    }
}

// open socket, auth once, read reply, return.
fn wnbind_try(user: &str, pass: &str) -> Result<(), PamError> {

    // connect to webnis-bind.
    let mut socket = match UnixStream::connect(SOCKADDR) {
        Ok(s) => s,
        Err(e) => {
            debug!("connect to {}: {}", SOCKADDR, e);
            return Err(from_io_error(e));
        },
    };
    socket.set_read_timeout(Some(Duration::from_millis(REQUEST_READ_TIMEOUT_MS))).ok();
    socket.set_write_timeout(Some(Duration::from_millis(REQUEST_WRITE_TIMEOUT_MS))).ok();

    // send request.
    let b = format!("auth {} {}\n", user, pass).into_bytes();
    if let Err(e) = socket.write_all(&b) {
        debug!("write to {}: {}", SOCKADDR, e);
        return Err(from_io_error(e));
    }

    // get reply.
    let mut line = String::new();
    let mut rdr = BufReader::new(socket);
    if let Err(e) = rdr.read_line(&mut line) {
        debug!("reading from {}: {}", SOCKADDR, e);
        return Err(from_io_error(e));
    }

    // Now decode the line.
    let mut s = line.splitn(2, ' ');
    let num = s.next().unwrap();

    let code = match num.parse::<u16>() {
        Ok(c) => c,
        Err(_) => {
            debug!("error: got garbage answer [{}]", line);
            return Err(PamError::AUTHINFO_UNAVAIL);
        },
    };

    match code {
        200 ... 299 => {
            Ok(())
        },
		401|403|404 => {
            debug!("error: {}", line);
            Err(PamError::AUTH_ERR)
		},
        _ => {
            debug!("error: {}", line);
            Err(PamError::AUTHINFO_UNAVAIL)
        }
    }
}

// call wnbind_try() and sleep/retry once if we fail.
fn wnbind_auth(user: &str, pass: &str) -> Result<(), PamError> {
    for tries in 0 .. MAX_TRIES {
        match wnbind_try(user, pass) {
            Ok(r) => return Ok(r),
            Err(PamError::AUTH_ERR) => return Err(PamError::AUTH_ERR),
            _ => {
                if tries < MAX_TRIES - 1 {
                    sleep(Duration::from_millis(RETRY_DELAY_MS));
                }
            },
        }
    }
    Err(PamError::AUTHINFO_UNAVAIL)
}

// helper.
fn from_io_error(e: std::io::Error) -> PamError {
    match e.kind() {
        std::io::ErrorKind::TimedOut|
        std::io::ErrorKind::Interrupted => PamError::AUTHINFO_UNAVAIL,
        _ => PamError::AUTH_ERR,
    }
}

