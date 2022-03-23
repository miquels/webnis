use pamsm::{PamServiceModule, PamFlags};

mod webnis;
pub use webnis::Webnis;

pamsm::pam_module!(Webnis);

