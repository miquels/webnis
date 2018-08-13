
use serde_json;

/// re-export the generic Error struct.
pub use failure::Error;

/// Errors in this crate.
#[derive(Debug, Fail)]
pub enum WnError {
    #[fail(display = "No such key in map")]
    KeyNotFound,
    #[fail(display = "No such map")]
    MapNotFound,
    #[fail(display = "Database error")]
    DbOther,
    #[fail(display = "Json serialization failed")]
    SerializeJson(#[cause] serde_json::Error),
    #[fail(display = "Data deserialization failed")]
    DeserializeData,
    #[fail(display = "Unknown format")]
    UnknownFormat,
    #[fail(display = "Failed to execute script function")]
    LuaError,
    #[fail(display = "Script function not found")]
    LuaFunctionNotFound,
    #[fail(display = "Failed")]
    Other,
}

#[allow(dead_code)]
pub(crate) fn multiline<'a>(s: &'a str) -> impl Iterator<Item = &'a str> {
    s.split('\n').filter(|l| l != &"")
}

pub use log::Level as LogLevel;

/// multi-line error. todo: tabs.
macro_rules! merror {
     ($($arg:tt)*) => (
        if log_enabled!(LogLevel::Error) {
            let txt = format!($($arg)*);
            $crate::errors::multiline(&txt).for_each(|m| error!("{}", m));
        }
    );
}

