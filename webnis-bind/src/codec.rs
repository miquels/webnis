
use std::io;

use tokio_codec;
use tokio_codec::{Encoder,Decoder};
use bytes::BytesMut;

/// A wrapper around tokio_codec::LinesCodec that also passes
/// a cloned context with the decoded line.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LinesCodec<T: Clone> {
    codec:      tokio_codec::LinesCodec,
    context:    T,
}

impl<T: Clone> LinesCodec<T> {
    pub fn new(ctx: T) -> LinesCodec<T> {
        LinesCodec{
            codec:      tokio_codec::LinesCodec::new(),
            context:    ctx,
        }
    }
}

impl<T: Clone> Decoder for LinesCodec<T> {
    type Item = (T, String);
    type Error = io::Error;

	fn decode(&mut self, mut buf: &mut BytesMut) -> Result<Option<(T, String)>, io::Error> {
		match self.codec.decode(&mut buf) {
            Ok(Some(line)) => Ok(Some((self.context.clone(), line))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
	}

    fn decode_eof(&mut self, mut buf: &mut BytesMut) -> Result<Option<(T, String)>, io::Error> {
		match self.codec.decode_eof(&mut buf) {
            Ok(Some(line)) => Ok(Some((self.context.clone(), line))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl<T: Clone> Encoder for LinesCodec<T> {
    type Item = String;
    type Error = io::Error;

    fn encode(&mut self, line: String, mut buf: &mut BytesMut) -> Result<(), io::Error> {
        self.codec.encode(line, &mut buf)
    }
}

