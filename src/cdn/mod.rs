//! Talking to Steam's content servers: directory discovery, HTTP client + retry matrix, and
//! the chunk decrypt/decompress/verify pipeline.

pub(crate) mod chunk;
pub(crate) mod client;
pub(crate) mod directory;

pub use directory::CdnServer;
