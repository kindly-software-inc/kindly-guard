// Binary protocol module for KindlyGuard Shield
// Provides high-performance binary encoding/decoding with zero-copy parsing

pub mod binary;
pub mod encoder;
pub mod decoder;
pub mod negotiator;
pub mod traits;

pub use binary::{BinaryMessage, MessageHeader, ProtocolVersion};
pub use encoder::BinaryEncoder;
pub use decoder::BinaryDecoder;
pub use negotiator::ProtocolNegotiator;
pub use traits::{ProtocolCodec, ProtocolError};

// Protocol version constants
pub const PROTOCOL_VERSION_1: u8 = 1;
pub const PROTOCOL_VERSION_BINARY: u8 = 2;
pub const PROTOCOL_MAGIC: [u8; 4] = [b'K', b'G', b'S', b'P']; // KindlyGuard Shield Protocol

#[cfg(test)]
mod tests;