#[macro_use] extern crate log;
#[macro_use] extern crate lazy_static;
extern crate env_logger;
extern crate pamsm;

mod webnis;

pub use webnis::get_pam_sm;
