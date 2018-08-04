use std;
use std::ptr::{write_bytes,copy_nonoverlapping};

use libc::{c_char, uid_t, gid_t, size_t, passwd, group};

use super::nss::NssError;

// Buffer as expected by NSS FFI API
// Used for both struct passwd and struct group.
#[derive(Debug)]
pub(crate) struct Buffer {
    buffer:     *mut c_char,
    buflen:     size_t,
    bufpos:     usize,
    res:        Result<(), NssError>,
}

impl Buffer {
    pub fn new(buffer: *mut c_char, buflen: size_t) -> Result<Buffer, NssError> {
        if buflen < 24 {
            return Err(NssError::InsufficientBuffer);
        }
        unsafe {
            write_bytes(buffer, 0, buflen);
        }
        Ok(Buffer {
            buffer:     buffer,
            buflen:     buflen,
            bufpos:     8,
            res:        Ok(()),
        })
    }

    /// reset the internal state.
    pub fn reset(&mut self) {
        unsafe {
            write_bytes(self.buffer, 0, self.buflen);
        }
        self.bufpos = 8;
        self.res = Ok(());
    }

    /// add a string to the buffer.
    pub fn add_string(&mut self, item: &str) -> Result<*mut c_char, NssError> {
        if let Err(ref err) = self.res {
            return Err(err.clone());
        }
        if self.bufpos + item.len() + 1 >= self.buflen {
            self.res = Err(NssError::InsufficientBuffer);
            return Err(NssError::InsufficientBuffer);
        }
        unsafe {
            let buf_cur = self.buffer.offset(self.bufpos as isize);
            copy_nonoverlapping(item.as_ptr(), buf_cur as *mut u8, item.len());
            self.bufpos += item.len() + 1;
            Ok(buf_cur)
        }
    }

    /// add an array of strings.
    pub fn add_members(&mut self, members: Vec<&str>) -> Result<*mut *mut c_char, NssError> {
        if let Err(ref err) = self.res {
            return Err(err.clone());
        }

        // first check if we have enough space for both the contents of
        // the vector and the C pointer array.
        let amt = members.len();
        let apos = 8 * ((self.bufpos + 7) / 8);
        let sz = (amt + 1) * std::mem::size_of::<*mut c_char>();
        if apos + sz >= self.buflen {
            self.res = Err(NssError::InsufficientBuffer);
            return Err(NssError::InsufficientBuffer);
        }

        // Create the pointer array.
        let (array, array_ptr) = unsafe {
            let buf_cur = self.buffer.offset(apos as isize);
            let buf_cur: *mut *mut c_char = buf_cur as *mut *mut c_char;
            self.bufpos = apos + sz;
            (std::slice::from_raw_parts_mut(buf_cur, amt + 1), buf_cur)
        };

        // Add vector items and set pointers.
        for idx in 0 .. members.len() {
            match self.add_string(&members[idx]) {
                Ok(ptr) => array[idx] = ptr,
                Err(e) => {
                    self.res = Err(e.clone());
                    return Err(e.clone());
                },
            }
        }

        Ok(array_ptr)
    }

    /// Get final result.
    fn result(&self) -> Result<(), NssError> {
        self.res.clone()
    }
}

/// Unix struct group.
pub struct Group {
    grp:        *mut group,
    buffer:     Buffer,
}

impl Group {
    /// Only for internal use.
    pub(crate) fn new(grp: *mut group, buffer: *mut c_char, buflen: size_t) -> Result<Group, NssError> {
        if grp.is_null() {
            return Err(NssError::Unavailable);
        }
        let mut grp = Group {
            grp:    grp,
            buffer: Buffer::new(buffer, buflen)?,
        };
        grp.reset();
        Ok(grp)
    }

    /// reset the internal state.
    pub fn reset(&mut self) {
        self.buffer.reset();
        unsafe {
            (*self.grp).gr_name = self.buffer.buffer;
            (*self.grp).gr_passwd = self.buffer.buffer;
            (*self.grp).gr_gid = 0;
            (*self.grp).gr_mem = self.buffer.buffer as *mut *mut c_char;
        }
    }

    /// set group name.
    pub fn set_name(&mut self, name: &str) {
        if let Ok(ptr) = self.buffer.add_string(name) {
            unsafe { (*self.grp).gr_name = ptr; }
        }
    }

    /// set group password.
    pub fn set_passwd(&mut self, pass: &str) {
        if let Ok(ptr) = self.buffer.add_string(pass) {
            unsafe { (*self.grp).gr_passwd = ptr; }
        }
    }

    /// set group id.
    pub fn set_gid(&mut self, gid: gid_t) {
        unsafe { (*self.grp).gr_gid = gid; }
    }

    /// set group members.
    pub fn set_members(&mut self, members: Vec<&str>) {
        if let Ok(ptr) = self.buffer.add_members(members) {
            unsafe { (*self.grp).gr_mem = ptr; }
        }
    }

    /// Get final result.
    pub fn result(&self) -> Result<(), NssError> {
        self.buffer.result()
    }
}

/// Unix struct Passwd.
#[derive(Debug)]
pub struct Passwd {
    pwd:        *mut passwd,
    buffer:     Buffer,
}

impl Passwd {
    /// Only for internal use.
    pub(crate)fn new(pwd: *mut passwd, buffer: *mut c_char, buflen: size_t) -> Result<Passwd, NssError> {
        if pwd.is_null() {
            return Err(NssError::Unavailable);
        }
        let mut pwd = Passwd {
            pwd:    pwd,
            buffer: Buffer::new(buffer, buflen)?,
        };
        pwd.reset();
        Ok(pwd)
    }

    /// reset the internal state.
    pub fn reset(&mut self) {
        self.buffer.reset();
        unsafe {
            (*self.pwd).pw_name = self.buffer.buffer;
            (*self.pwd).pw_passwd = self.buffer.buffer;
            (*self.pwd).pw_uid = 0;
            (*self.pwd).pw_gid = 0;
            (*self.pwd).pw_gecos = self.buffer.buffer;
            (*self.pwd).pw_dir = self.buffer.buffer;
            (*self.pwd).pw_shell = self.buffer.buffer;
        }
    }

    /// set user name.
    pub fn set_name(&mut self, name: &str) {
        if let Ok(ptr) = self.buffer.add_string(name) {
            unsafe { (*self.pwd).pw_name = ptr; }
        }
    }

    /// set user password.
    pub fn set_passwd(&mut self, pass: &str) {
        if let Ok(ptr) = self.buffer.add_string(pass) {
            unsafe { (*self.pwd).pw_passwd = ptr; }
        }
    }

    /// set user id.
    pub fn set_uid(&mut self, uid: uid_t) {
        unsafe { (*self.pwd).pw_uid = uid; }
    }

    /// set user id.
    pub fn set_gid(&mut self, gid: gid_t) {
        unsafe { (*self.pwd).pw_gid = gid; }
    }

    /// set user gecos.
    pub fn set_gecos(&mut self, gecos: &str) {
        if let Ok(ptr) = self.buffer.add_string(gecos) {
            unsafe { (*self.pwd).pw_gecos = ptr; }
        }
    }

    /// set user homedir.
    pub fn set_home(&mut self, dir: &str) {
        if let Ok(ptr) = self.buffer.add_string(dir) {
            unsafe { (*self.pwd).pw_dir = ptr; }
        }
    }

    /// set user shell.
    pub fn set_shell(&mut self, shell: &str) {
        if let Ok(ptr) = self.buffer.add_string(shell) {
            unsafe { (*self.pwd).pw_shell = ptr; }
        }
    }

    /// Get final result.
    pub fn result(&self) -> Result<(), NssError> {
        self.buffer.result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::slice;

    #[test]
    fn t_buffer() {
        let mut bbuf = [0u8; 1024];
        {
            let mut buf = Buffer::new(bbuf.as_mut_ptr() as *mut c_char, 1024).unwrap();
            buf.add_string("Hello").unwrap();
            buf.add_string("World").unwrap();
        }
        assert_eq!(&bbuf[0..20], b"\0\0\0\0\0\0\0\0Hello\0World\0");
    }

    #[test]
    fn t_passwd() {
        let mut bbuf = [0u8; 1024];
        let mut pwd : passwd = unsafe { std::mem::zeroed() };

        // set some data.
        let mut pwdb = Passwd::new(&mut pwd as *mut passwd, bbuf.as_mut_ptr() as *mut c_char, 1024).unwrap();
        pwdb.set_name("mikevs");
        pwdb.set_passwd("x");
        pwdb.set_uid(1000);
        pwdb.set_gid(50);
        pwdb.set_gecos("gecos");
        pwdb.set_home("/home/mikevs");
        pwdb.set_shell("/bin/sh");

        // in the expected memory layout?
        assert_eq!(&bbuf[0..15], b"\0\0\0\0\0\0\0\0mikevs\0");
        assert_eq!(&bbuf[15..36], b"x\0gecos\0/home/mikevs\0");
        assert_eq!(&bbuf[36..44], b"/bin/sh\0");

        // check struct passwd pointers.
        assert_eq!(unsafe { CStr::from_ptr(pwd.pw_name) }.to_str().unwrap(), "mikevs");
        assert_eq!(unsafe { CStr::from_ptr(pwd.pw_passwd) }.to_str().unwrap(), "x");
        assert_eq!(pwd.pw_uid, 1000);
        assert_eq!(pwd.pw_gid, 50);
        assert_eq!(unsafe { CStr::from_ptr(pwd.pw_gecos) }.to_str().unwrap(), "gecos");
        assert_eq!(unsafe { CStr::from_ptr(pwd.pw_dir) }.to_str().unwrap(), "/home/mikevs");
        assert_eq!(unsafe { CStr::from_ptr(pwd.pw_shell) }.to_str().unwrap(), "/bin/sh");
    }

    #[test]
    fn t_group() {
        let mut bbuf = [0u8; 1024];
        let mut grp : group = unsafe { std::mem::zeroed() };

        let mut grpb = Group::new(&mut grp as *mut group, bbuf.as_mut_ptr() as *mut c_char, 1024).unwrap();

        // see if zero-initialized correctly.
        assert!(!grp.gr_mem.is_null());
        let pptr: &mut [*mut c_char] = unsafe {
            slice::from_raw_parts_mut(grp.gr_mem, 1)
        };
        assert!(pptr[0].is_null());
        assert_eq!(unsafe { CStr::from_ptr(grp.gr_name) }.to_str().unwrap(), "");
        assert_eq!(unsafe { CStr::from_ptr(grp.gr_passwd) }.to_str().unwrap(), "");

        // set some data.
        grpb.set_name("users");
        grpb.set_passwd("x");
        grpb.set_gid(50);
        grpb.set_members(vec!["piet", "jan", "henk"]);

        // in the expected memory layout?
        assert_eq!(&bbuf[0..16], b"\0\0\0\0\0\0\0\0users\0x\0");

        // check struct group pointers.
        assert_eq!(unsafe { CStr::from_ptr(grp.gr_name) }.to_str().unwrap(), "users");
        assert_eq!(unsafe { CStr::from_ptr(grp.gr_passwd) }.to_str().unwrap(), "x");
        assert_eq!(grp.gr_gid, 50);
        let pptr: &mut [*mut c_char] = unsafe {
            slice::from_raw_parts_mut(grp.gr_mem, 4)
        };
        assert_eq!(unsafe { CStr::from_ptr(pptr[0]) }.to_str().unwrap(), "piet");
        assert_eq!(unsafe { CStr::from_ptr(pptr[1]) }.to_str().unwrap(), "jan");
        assert_eq!(unsafe { CStr::from_ptr(pptr[2]) }.to_str().unwrap(), "henk");
        assert!(pptr[3].is_null());
    }
}

