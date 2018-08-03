use std;
use std::mem;
use std::time::Duration;
use std::os::unix::net::UnixStream;
use std::io::{BufRead,BufReader};
use std::thread::sleep;
use std::io::Write;
use std::ptr;
use std::ffi::CStr;
use std::os::raw::{c_char,c_void};

use pamsm::{self,PamServiceModule};
use pamsm::pam_raw::{pam_get_item,pam_get_user,PamFlag,PamError,PamItemType,PamHandle};

static SOCKADDR: &'static str = "/var/run/webnis-bind.sock";

// doc sources used:
// https://github.com/vyos/libpam-radius-auth/blob/current/src/pam_radius_auth.h
// https://github.com/vyos/libpam-radius-auth/blob/current/src/pam_radius_auth.c
// https://github.com/rcatolino/pam_sm_rust/blob/master/src/pam_raw.rs
// https://linux.die.net/man/3/pam_authenticate
// https://linux.die.net/man/3/pam_get_item

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

// init callback from pam-raw to this module.
#[no_mangle]
pub extern "C" fn get_pam_sm() -> Box<PamServiceModule> {
    return Box::new(Webnis);
}

// type to impl the PamServiceModule on.
pub struct Webnis;

impl PamServiceModule for Webnis {
    fn authenticate(self: &Self, pampam: pamsm::Pam, _pam_flags: PamFlag, args: Vec<String>) -> PamError {

        // config file cmdline args.
        let pam_args = PamArgs::parse(&args);
        if (pam_args & PamArgs::DEBUG as u32) != 0 {
            DEBUG();
        }

        // yolo. there is no way to access PamHandle otherwise.
        let pamh = unsafe { mem::transmute::<pamsm::Pam, PamHandle>(pampam) };

        // get username
        let user = unsafe {
            let mut user: *const c_char = ptr::null();
            let res = pam_get_user(pamh, &mut user as *mut *const c_char, ptr::null());
            if res != PamError::SUCCESS as i32 {
                // error[E0624]: method `new` is private
                return to_pam_error(res);
            }
            if user.is_null() {
                return PamError::USER_UNKNOWN;
            }
            match std::str::from_utf8(CStr::from_ptr(user).to_bytes()) {
                Ok(s) => s,
                Err(_) => return PamError::USER_UNKNOWN,
            }
        };

        // get password
        let pass = unsafe {
            // we always act in "use_first_pass" mode.
            let mut pass: *const c_void = ptr::null();
            let res = pam_get_item(pamh, PamItemType::AUTHTOK as i32, &mut pass as *mut *const c_void);
            if res != PamError::SUCCESS as i32 {
                return to_pam_error(res);
            }
            if pass.is_null() {
                return PamError::AUTH_ERR;
            }
            let pass = mem::transmute::<*const c_void, *const c_char>(pass);
            match std::str::from_utf8(CStr::from_ptr(pass).to_bytes()) {
                Ok(s) => s,
                Err(_) => return PamError::AUTH_ERR,
            }
        };

        // run authentication.
        match wnbind_auth(user, pass) {
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
    socket.set_read_timeout(Some(Duration::new(3, 0))).ok();
    socket.set_write_timeout(Some(Duration::new(1, 0))).ok();

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

// call wnbind_try and sleep/retry a few times if we fail.
fn wnbind_auth(user: &str, pass: &str) -> Result<(), PamError> {
    let max_tries = 2;
    for tries in 0 .. max_tries {
        match wnbind_try(user, pass) {
            Ok(r) => return Ok(r),
            Err(PamError::AUTH_ERR) => return Err(PamError::AUTH_ERR),
            _ => {
                if tries < max_tries - 1 {
                    sleep(Duration::new(3, 0));
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

// more helpers because the pamsm crate is not quite complete.
//      let code = PamError::new(some_i32_val);
//      ---> error[E0624]: method `new` is private
// FIXME file "pamsm" bugreport.
const AUTH_ERR : i32 = PamError::AUTH_ERR as i32;
const SUCCESS : i32 = PamError::SUCCESS as i32;
const USER_UNKNOWN : i32 = PamError::USER_UNKNOWN as i32;
//const AUTHINFO_UNAVAIL : i32 = PamError::AUTH_ERR as i32;

fn to_pam_error(e: i32) -> PamError {
    match e {
		AUTH_ERR => PamError::AUTH_ERR,
		SUCCESS => PamError::SUCCESS,
		USER_UNKNOWN => PamError::USER_UNKNOWN,
		// AUTHINFO_UNAVAIL => PamError::AUTHINFO_UNAVAIL,
		_ => PamError::AUTHINFO_UNAVAIL,
	}
}

