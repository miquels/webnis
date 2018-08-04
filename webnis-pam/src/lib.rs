#[macro_use] extern crate log;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate pamsm;
extern crate env_logger;

mod webnis;
pub use webnis::Webnis;

pamsm_init!(Box::new(Webnis));

