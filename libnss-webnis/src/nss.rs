use std;
use std::ffi::CStr;
use std::ptr::{write_bytes,copy_nonoverlapping};

use libc;
use libc::{c_void, c_char, uid_t, gid_t, size_t, passwd, group};
use libc::{ENOENT, EAGAIN, ERANGE};

use webnis;
use errors::{BufferFillError, BufferFillResult};

/// NssStatus is the return value from libnss-called functions.
/// They are cast to i32 when being returned.
enum NssStatus {
    TryAgain = -2,
    Unavailable,
    NotFound,
    Success, // NssStatusReturn exists in passwd.h but is not used here
}


/// _initgroups_dyn generates the data for getgrouplist(3).
///
/// It is an optimization- if _initgroups_dyn is not available in
/// an NSS module, the NSS runtime will generate the same data
/// using setgrent() - getgrent_r() - endgrent().
///
/// This also means that if getgrent_r() is not available in this
/// NSS module, but _initgroups_dyn is, getgrouplist() still works.
///
/// The following argument descriptions come from the libnss-ldap package:
///
///   name      IN     - the user name to find group-ids for
///   skipgid   IN     - a group-id to not include in the list
///   *start    IN/OUT - where to write in the array, is incremented
///   *size     IN/OUT - the size of the supplied array (gid_t entries, not bytes)
///   **gidsp   IN/OUT - pointer to the array of returned group-ids
///   limit     IN     - the maximum size of the array
///   *errnop   OUT    - for returning errno
#[no_mangle]
pub extern "C" fn _nttp_webnis_initgroups_dyn(name: *const c_char,
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
        Err(_) => {
            return nss_entry_not_available(errnop);
        }
    };
    #[cfg(debug_assertions)]
    println!("libnss-http initgroups_dyn called for {}", name);

    let gidline = match webnis::get_user_gids(name) {
        Ok(v) => v,
        Err(_err) => {
            #[cfg(debug_assertions)]
             println!("libnss-http: _initgroups_dyn failed for {}: {:?}", name, _err);
            return nss_entry_not_available(errnop);
        }
    };

    // split into name and gidlist..
    let fields = gidline.split(':').collect::<Vec<&str>>();
    if fields.len() != 2 {
        return nss_entry_not_available(errnop);
    }
    // parse gidlist into Vec<gid_t>
    let mut user_gids = Vec::new();
    for v in fields[1].split(',') {
        let gid = match v.parse::<gid_t>() {
            Ok(v) => v,
            Err(_err) => return nss_entry_not_available(errnop),
        };
        if gid != skipgid {
            user_gids.push(gid);
        }
    }

    // If we get no gids, then we have nothing to do.
    if user_gids.is_empty() {
        #[cfg(debug_assertions)]
        println!("libnss-http: _initgroups_dyn: no user groups for {}", name);
        return NssStatus::Success as i32;
    }

    // How big is the array we were passed, and how deep into it are we?
    let mut idx = unsafe { *start };
    let mut gid_arraysz = unsafe { *size };
    #[cfg(debug_assertions)]
    println!("libnss-http gids array size={}@idx {}, adding {}",
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

/// The `getgrnam` function retrieves information about the named group.
///
/// The `result` argument is a pointer to an already-allocated C struct group,
/// which consists of member pointers. The information that is looked up is
/// stored in `buffer`, and `result`'s pointers point into the buffer.
#[no_mangle]
pub extern "C" fn _nttp_webnis_getgrnam_r(name: *const c_char,
                                      result: *mut group,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!result.is_null() && !buffer.is_null() && !errnop.is_null());

    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            return nss_entry_not_available(errnop);
        }
    };
    #[cfg(debug_assertions)]
    println!("libnss-http getgrnam_r called for {}", name);

    let groupline = match webnis::get_group_by_name(name) {
        Ok(v) => v,
        Err(err) => {
            #[cfg(debug_assertions)]
            println!("libnss-http failed to lookup group {}: {:?}", name, err);
            return nss_entry_not_available(errnop);
        }
    };

    match fill_group_buf(result, buffer, buflen, &groupline) {
        Ok(()) => NssStatus::Success as i32,
        Err(BufferFillError::InsufficientBuffer) => nss_insufficient_buffer(errnop),
        Err(_e) => {
            #[cfg(debug_assertions)]
            println!("libnss-http getgrnam_r failed because {:?}", _e);
            nss_entry_not_available(errnop)
        }
    }
}

/// getgrgid is like getgrnam, but the lookup key is the group-id.
#[no_mangle]
pub extern "C" fn _nttp_webnis_getgrgid_r(gid: gid_t,
                                      result: *mut group,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!result.is_null() && !buffer.is_null() && !errnop.is_null());

    #[cfg(debug_assertions)]
    println!("libnss-http getgrgid_r called for {}", gid);

    let groupline = match webnis::get_group_by_gid(gid) {
        Ok(v) => v,
        Err(err) => {
            #[cfg(debug_assertions)]
            println!("libnss-http: _getgrgid_r: failed to lookup group {}: {:?}", gid, err);
            return nss_entry_not_available(errnop);
        }
    };

    match fill_group_buf(result, buffer, buflen, &groupline) {
        Ok(()) => NssStatus::Success as i32,
        Err(BufferFillError::InsufficientBuffer) => nss_insufficient_buffer(errnop),
        Err(_e) => {
            #[cfg(debug_assertions)]
            println!("libnss-http: _getgrnam_r: failed because {:?}", _e);
            nss_entry_not_available(errnop)
        }
    }
}

/// The `getpwnam` function retrieves information about the named user.
///
/// The `result` argument is a pointer to an already-allocated C struct passwd,
/// which consists of member pointers. The information that is looked up is
/// stored in `buffer`, and `result`'s pointers point into the buffer.
#[no_mangle]
pub extern "C" fn _nttp_webnis_getpwnam_r(name: *const c_char,
                                      result: *mut passwd,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!result.is_null() && !buffer.is_null() && !errnop.is_null());

    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            return nss_entry_not_available(errnop);
        }
    };
    #[cfg(debug_assertions)]
    println!("libnss-http getpwnam_r called for {}", name);

    let passwdline = match webnis::get_user_by_name(name) {
        Ok(v) => v,
        Err(err) => {
            #[cfg(debug_assertions)]
            println!("libnss-http failed to lookup user {}: {:?}", name, err);
            return nss_entry_not_available(errnop);
        }
    };

    match fill_passwd_buf(result, buffer, buflen, &passwdline) {
        Ok(()) => NssStatus::Success as i32,
        Err(BufferFillError::InsufficientBuffer) => nss_insufficient_buffer(errnop),
        Err(_e) => {
            #[cfg(debug_assertions)]
            println!("libnss-http getpwnam_r failed because {:?}", _e);
            nss_entry_not_available(errnop)
        }
    }
}

/// getpwuid is like getpwnam, but the lookup key is the user-id.
#[no_mangle]
pub extern "C" fn _nttp_webnis_getpwuid_r(uid: uid_t,
                                      result: *mut passwd,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!result.is_null() && !buffer.is_null() && !errnop.is_null());

    #[cfg(debug_assertions)]
    println!("libnss-http getpwuid_r called for {}", uid);

    let passwdline = match webnis::get_user_by_uid(uid) {
        Ok(v) => v,
        Err(err) => {
            #[cfg(debug_assertions)]
            println!("libnss-http failed to lookup user {}: {:?}", uid, err);
            return nss_entry_not_available(errnop);
        }
    };

    match fill_passwd_buf(result, buffer, buflen, &passwdline) {
        Ok(()) => NssStatus::Success as i32,
        Err(BufferFillError::InsufficientBuffer) => nss_insufficient_buffer(errnop),
        Err(_e) => {
            #[cfg(debug_assertions)]
            println!("libnss-http getpwuid_r failed because {:?}", _e);
            nss_entry_not_available(errnop)
        }
    }
}

/// This function accepts a line in the /etc/group format, and copies the
/// content into the buffer provided to store the contents of the provided
/// C struct group.
fn fill_group_buf(gr: *mut group,
                  buffer: *mut c_char,
                  buflen: size_t,
                  grpline: &str)
                  -> BufferFillResult<()> {
    // sanity checks.
    if gr.is_null() || buffer.is_null() || buflen == 0 {
        return Err(BufferFillError::NullPointerError);
    }
    if grpline.as_bytes().contains(&0) {
        return Err(BufferFillError::ZeroByteInString);
    }

    // split up group line into fields and members.
    let grfields: Vec<&str> = grpline.split(':').collect();
    if grfields.len() != 4 {
        return Err(BufferFillError::DecodeError);
    }
    let members: Vec<&str> = grfields[3].split(',').collect();

    // enough space in "buffer"? if not, let caller retry with a bigger buffer.
    let members_array_sz = std::mem::size_of::<*mut c_char>() * (members.len() + 1);
    if buflen < grpline.len() + members_array_sz {
        return Err(BufferFillError::InsufficientBuffer);
    }

    // parse numeric fields.
    unsafe {
        (*gr).gr_gid = grfields[2].parse::<gid_t>().map_err(|_| BufferFillError::DecodeError)?;
    }
    // allocate space for the array of pointers to member names.
    unsafe { write_bytes(buffer, 0, buflen); };
    let buf_cur: *mut *mut c_char = buffer as *mut *mut c_char;
    let members_array: &mut [*mut c_char] =
        unsafe { std::slice::from_raw_parts_mut(buf_cur, members.len() + 1) };

    // after the array of pointers we put the C strings.
    let mut buf_cur: *mut c_char = unsafe { buf_cur.offset(members.len() as isize + 1) as *mut c_char };

    // copy gr_name, gr_passwd.
    unsafe {
        let field = grfields[0];
        copy_nonoverlapping(field.as_ptr(), buf_cur as *mut u8, field.len());
        (*gr).gr_name = buf_cur;
        buf_cur = buf_cur.offset(field.len() as isize + 1);

        let field = grfields[1];
        copy_nonoverlapping(field.as_ptr(), buf_cur as *mut u8, field.len());
        (*gr).gr_passwd = buf_cur;
        buf_cur = buf_cur.offset(field.len() as isize + 1);
    }

    // and the member names.
    let mut idx = 0;
    for member in members {
        unsafe {
            copy_nonoverlapping(member.as_ptr(), buf_cur as *mut u8, member.len());
            members_array[idx] = buf_cur;
            idx += 1;
            buf_cur = buf_cur.offset(member.len() as isize + 1);
        }
    }

    Ok(())
}

/// This function accepts a line in the /etc/passwd format, and copies the
/// content into the buffer provided to store the contents of the provided
/// C struct passwd.
fn fill_passwd_buf(pw: *mut passwd,
                   buffer: *mut c_char,
                   buflen: size_t,
                   pwdline: &str)
                   -> BufferFillResult<()> {
    // sanity checks.
    if pw.is_null() || buffer.is_null() || buflen == 0 {
        return Err(BufferFillError::NullPointerError);
    }
    if pwdline.as_bytes().contains(&0) {
        return Err(BufferFillError::ZeroByteInString);
    }

    // split up passwd line into fields.
    let pwfields: Vec<&str> = pwdline.split(':').collect();
    if pwfields.len() != 7 {
        return Err(BufferFillError::DecodeError);
    }

    // enough space in "buffer"? if not, let caller retry with a bigger buffer.
    if buflen < pwdline.len() {
        return Err(BufferFillError::InsufficientBuffer);
    }

    // parse numeric fields.
    unsafe {
        (*pw).pw_uid = pwfields[2].parse::<uid_t>().map_err(|_| BufferFillError::DecodeError)?;
        (*pw).pw_gid = pwfields[3].parse::<gid_t>().map_err(|_| BufferFillError::DecodeError)?;
    }

    // copy fields.
    let mut buf_cur = buffer;
    unsafe {
        write_bytes(buf_cur, 0, buflen);

        let field = pwfields[0];
        copy_nonoverlapping(field.as_ptr(), buf_cur as *mut u8, field.len());
        (*pw).pw_name = buf_cur;
        buf_cur = buf_cur.offset(field.len() as isize + 1);

        let field = pwfields[1];
        copy_nonoverlapping(field.as_ptr(), buf_cur as *mut u8, field.len());
        (*pw).pw_passwd = buf_cur;
        buf_cur = buf_cur.offset(field.len() as isize + 1);

        let field = pwfields[4];
        copy_nonoverlapping(field.as_ptr(), buf_cur as *mut u8, field.len());
        (*pw).pw_gecos = buf_cur;
        buf_cur = buf_cur.offset(field.len() as isize + 1);

        let field = pwfields[5];
        copy_nonoverlapping(field.as_ptr(), buf_cur as *mut u8, field.len());
        (*pw).pw_dir = buf_cur;
        buf_cur = buf_cur.offset(field.len() as isize + 1);

        let field = pwfields[6];
        copy_nonoverlapping(field.as_ptr(), buf_cur as *mut u8, field.len());
        (*pw).pw_shell = buf_cur;
    }

    Ok(())
}

/// One of the functions used ran temporarily out of resources
/// or a service is currently not available.
fn nss_out_of_service(errnop: *mut i32) -> i32 {
    unsafe { *errnop = EAGAIN };
    NssStatus::TryAgain as i32
}

/// The provided buffer is not large enough. The function should
/// be called again with a larger buffer.
fn nss_insufficient_buffer(errnop: *mut i32) -> i32 {
    unsafe { *errnop = ERANGE };
    NssStatus::TryAgain as i32
}

/// A necessary input file cannot be found.
fn nss_input_file_err(errnop: *mut i32) -> i32 {
    unsafe { *errnop = ENOENT };
    NssStatus::Unavailable as i32
}

/// The requested entry is not available.
fn nss_entry_not_available(errnop: *mut i32) -> i32 {
    unsafe { *errnop = ENOENT };
    NssStatus::NotFound as i32
}
