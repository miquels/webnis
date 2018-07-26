
use std;

pub type BufferFillResult<T> = Result<T, BufferFillError>;

#[derive(Debug)]
pub enum BufferFillError {
    InsufficientBuffer,
    NullPointerError,
    ZeroByteInString,
    DecodeError,
}

impl From<std::ffi::NulError> for BufferFillError {
    fn from(_: std::ffi::NulError) -> BufferFillError {
        BufferFillError::ZeroByteInString
    }
}

pub type ConnxResult<T> = Result<T, ConnxRetrievalError>;

#[derive(Debug)]
pub enum ConnxRetrievalError {
    NotFound,
    Unavailable,
    TryAgain,
}

