// This file contains the raw _libnss_* ffi entrance points
use std;
use std::ffi::CStr;

use libc;
use libc::{c_void, c_char, size_t, group, passwd};
use libc::{ENOENT, EAGAIN, ERANGE, ETIMEDOUT};

pub use super::buffer::{Passwd,Group};
pub use libc::{uid_t, gid_t};

use super::webnis::Webnis;

thread_local! {
    static NSS: Webnis = Webnis::new();
}

/// NSS FFI entry point for _initgroups_dyn()
///
/// _initgroups_dyn generates the data for getgrouplist(3).
///
/// It is an optimization- if _initgroups_dyn is not available in
/// an NSS module, the NSS runtime will generate the same data
/// using setgrent() - getgrent_r() - endgrent().
///
/// This also means that if getgrent_r() is not available in this
/// NSS module, but _initgroups_dyn is, getgrouplist() still works.
//
// The following argument descriptions come from the libnss-ldap package:
//
//   name      IN     - the user name to find group-ids for
//   skipgid   IN     - a group-id to not include in the list
//   *start    IN/OUT - where to write in the array, is incremented
//   *size     IN/OUT - the size of the supplied array (gid_t entries, not bytes)
//   **gidsp   IN/OUT - pointer to the array of returned group-ids
//   limit     IN     - the maximum size of the array
//   *errnop   OUT    - for returning errno
#[no_mangle]
pub extern "C" fn _nss_webnis_initgroups_dyn(name: *const c_char,
                                          skipgid: gid_t,
                                          start: *mut size_t,
                                          size: *mut size_t,
                                          gidsp: *mut *mut gid_t,
                                          limit: size_t,
                                          errnop: *mut i32)
                                          -> i32 {

    assert!(!gidsp.is_null() && !name.is_null() && !start.is_null() && !size.is_null());

    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => return nss_error(NssError::Unavailable, errnop),
    };
    debug!("libnss-http initgroups_dyn called for {}", name);

    let user_gids = match NSS.with(|nss| nss.getgidlist(name)) {
        Ok(gids) => gids,
        Err(e) => return nss_error(e, errnop),
    };
    let user_gids : Vec<gid_t> = user_gids.into_iter().filter(|&g| g != skipgid).collect();

    // If we get no gids, then we have nothing to do.
    if user_gids.is_empty() {
        debug!("libnss-http: _initgroups_dyn: no user groups for {}", name);
        return NssStatus::Success as i32;
    }

    // How big is the array we were passed, and how deep into it are we?
    let mut idx = unsafe { *start };
    let mut gid_arraysz = unsafe { *size };
    debug!("libnss-http gids array size={}@idx {}, adding {}",
             gid_arraysz,
             idx,
             user_gids.len());
    if idx + user_gids.len() > gid_arraysz {
        // We need to add more group IDs to the array than we currently have space for
        let new_sz = idx + user_gids.len();
        let new_sz = if limit == 0 { new_sz } else { std::cmp::min(new_sz, limit) };
        let new_sz = new_sz * std::mem::size_of::<gid_t>();
        unsafe {
            *gidsp = libc::realloc(*gidsp as *mut c_void, new_sz) as *mut gid_t;
            *size = new_sz;
        }
        gid_arraysz = new_sz;
    }

    // Now that we've got the memory we need, build a raw slice into which
    // we can copy values out of the Rust user_gids Vec.
    let gid_array: &mut [gid_t] =
        unsafe { std::slice::from_raw_parts_mut(*gidsp, gid_arraysz) };

    for gid in user_gids {
        // Copy the GID into the raw slice
        gid_array[idx] = gid;
        // keeping track of the index (which must be returned to the caller)
        idx += 1;
        if idx == limit {
            // if we run out of space, bail
            break;
        }
    }

    unsafe {
        *start = idx; // Next NSS module will start filling the array here.
    }

    NssStatus::Success as i32
}

/// NSS FFI entry point for getgrnam_r()
#[no_mangle]
pub extern "C" fn _nss_webnis_getgrnam_r(name: *const c_char,
                                      result: *mut group,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!result.is_null() && !buffer.is_null() && !errnop.is_null());

    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => return nss_error(NssError::Unavailable, errnop),
    };
    debug!("libnss-http getgrnam_r called for {}", name);

    let group = match Group::new(result, buffer, buflen) {
        Ok(g) => g,
        Err(e) => return nss_error(e, errnop),
    };

    let res = NSS.with(|nss| nss.getgrnam(group, name));
    return nss_result(res, errnop);
}

/// NSS FFI entry point for getgrgid_r()
#[no_mangle]
pub extern "C" fn _nss_webnis_getgrgid_r(gid: gid_t,
                                      result: *mut group,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!result.is_null() && !buffer.is_null() && !errnop.is_null());
    debug!("libnss-http getgrgid_r called for {}", gid);

    let group = match Group::new(result, buffer, buflen) {
        Ok(g) => g,
        Err(e) => return nss_error(e, errnop),
    };

    let res = NSS.with(|nss| nss.getgrgid(group, gid));
    return nss_result(res, errnop);
}

/// NSS FFI entry point for getpwnam_r()
#[no_mangle]
pub extern "C" fn _nss_webnis_getpwnam_r(name: *const c_char,
                                      result: *mut passwd,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!result.is_null() && !buffer.is_null() && !errnop.is_null());

    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => return nss_error(NssError::Unavailable, errnop),
    };
    debug!("libnss-http getpwnam_r called for {}", name);

    let passwd = match Passwd::new(result, buffer, buflen) {
        Ok(g) => g,
        Err(e) => return nss_error(e, errnop),
    };

    let res = NSS.with(|nss| nss.getpwnam(passwd, name));
    return nss_result(res, errnop);
}

/// NSS FFI entry point for getpwuid_r()
#[no_mangle]
pub extern "C" fn _nss_webnis_getpwuid_r(uid: uid_t,
                                      result: *mut passwd,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!result.is_null() && !buffer.is_null() && !errnop.is_null());
    debug!("libnss-http getpwuid_r called for {}", uid);

    let passwd = match Passwd::new(result, buffer, buflen) {
        Ok(p) => p,
        Err(e) => return nss_error(e, errnop),
    };

    let res = NSS.with(|nss| nss.getpwuid(passwd, uid));
    return nss_result(res, errnop);
}

/// NssStatus is the return value from libnss-called functions.
/// They are cast to i32 when being returned.
enum NssStatus {
    TryAgain = -2,
    Unavailable,
    NotFound,
    Success, // NssStatusReturn exists in passwd.h but is not used here
}

/// Result type helper.
pub type NssResult<T> = Result<T, NssError>;

/// Errors.
#[derive(Debug, Clone)]
pub enum NssError {
    // Caller didn't supply enough buffer space.
    InsufficientBuffer,
    // Entry was not found.
    NotFound,
    // Something went permanently wrong.
    Unavailable,
    // Something went temporarily wrong.
    TryAgain,
    // Timed out.
    TimedOut,
}

impl From<std::ffi::NulError> for NssError {
    fn from(_: std::ffi::NulError) -> NssError {
		NssError::Unavailable
    }
}

impl From<std::io::Error> for NssError {
    fn from(e: std::io::Error) -> NssError {
        match e.kind() {
            std::io::ErrorKind::TimedOut|
            std::io::ErrorKind::Interrupted => NssError::TimedOut,
		    _ => NssError::Unavailable,
        }
    }
}

fn nss_error(err: NssError, errnop: *mut i32) -> i32 {
    let (errno, status) = match err {
        NssError::InsufficientBuffer => (ERANGE, NssStatus::TryAgain),
        NssError::NotFound => (ENOENT, NssStatus::NotFound),
        NssError::Unavailable => (EAGAIN, NssStatus::Unavailable),
        NssError::TryAgain => (EAGAIN, NssStatus::TryAgain),
        NssError::TimedOut => (ETIMEDOUT, NssStatus::TryAgain),
    };
    unsafe { *errnop = errno };
    status as i32
}

fn nss_result<T>(res: NssResult<T>, errnop: *mut i32) -> i32 {
    match res {
        Ok(_) => NssStatus::Success as i32,
        Err(err) => nss_error(err, errnop),
    }
}

