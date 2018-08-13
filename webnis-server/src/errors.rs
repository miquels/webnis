
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
    #[fail(display = "Failed")]
    Other,
}

