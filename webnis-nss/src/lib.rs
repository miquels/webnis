#[macro_use] extern crate log;
extern crate env_logger;
extern crate libc;

mod webnis;
mod nss;
mod buffer;

pub use nss::_nss_webnis_initgroups_dyn;
pub use nss::_nss_webnis_getgrnam_r;
pub use nss::_nss_webnis_getgrgid_r;
pub use nss::_nss_webnis_getpwnam_r;
pub use nss::_nss_webnis_getpwuid_r;

