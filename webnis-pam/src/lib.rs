#[macro_use] extern crate pamsm;
extern crate percent_encoding;

mod webnis;
pub use webnis::Webnis;

pamsm_init!(Box::new(Webnis));

