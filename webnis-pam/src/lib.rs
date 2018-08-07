#[macro_use] extern crate log;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate pamsm;
extern crate env_logger;
extern crate percent_encoding;

mod webnis;
pub use webnis::Webnis;

pamsm_init!(Box::new(Webnis));

