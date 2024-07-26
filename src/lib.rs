//! An implementation of ECC based blind signatures.
//!
//! # Based On Paper
//!
//! Mathematical syntax from this documentation is taken from the paper
//! [Blind Signature Scheme Based on Elliptic Curve Cryptography](pdfs.semanticscholar.org/e58a/1713858a9e18abfc05de244e.pdf).
//!
//! # Note
//!
//! This is a sans-IO implementation, meaning that no network IO for requesting
//! or granting the initiation of the protocol is provided by this crate.

use log::LevelFilter;
use thiserror::Error;

// The public interface
pub mod keypair;
pub mod request;
pub mod session;
pub mod signature;

/// The Result type used
pub type Result<T> = std::result::Result<T, Error>;

// Re-export Error and Result for use in other modules
pub use self::Error;

/// Initialize the logger for the blindsign library.
/// This function should be called at the start of the main program using this library.
pub fn init_logger() {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Debug)
        .init();
}

/// The Error types
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to initialize the RNG")]
    RngInitFailed,
    #[error("failed to convert wired scalar to scalar")]
    WiredScalarMalformed,
    #[error("failed to convert wired ristretto point to ristretto point")]
    WiredRistrettoPointMalformed,
}

impl From<rand::Error> for Error {
    fn from(_: rand::Error) -> Self {
        Error::RngInitFailed
    }
}
