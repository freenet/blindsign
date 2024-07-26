//! Signer side of the blind signature protocol

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use log::debug;
use crate::Error::WiredScalarMalformed;
use crate::Result;

/// Manages the signer side of the blind signature protocol.
pub struct BlindSigner {
    k: Scalar,
}

impl BlindSigner {
    /// Initiates a new signer session.
    ///
    /// # Returns
    ///
    /// * `Ok(([u8; 32], BlindSigner))` - The R' value to send to the client, and the BlindSigner instance.
    /// * `Err(Error)` - If there's an error in the process.
    pub fn new() -> Result<([u8; 32], Self)> {
        let k = Scalar::from_bytes_mod_order(rand::random());
        let rp = (k * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        Ok((rp, Self { k }))
    }

    /// Signs the blinded message.
    ///
    /// # Arguments
    ///
    /// * `ep` - The e' value received from the client.
    /// * `xs` - The signer's private key.
    ///
    /// # Returns
    ///
    /// * `Ok([u8; 32])` - The blind signature S'.
    /// * `Err(Error)` - If there's an error in the process.
    pub fn sign(self, ep: &[u8; 32], xs: Scalar) -> Result<[u8; 32]> {
        debug!("ep bytes: {:?}", ep);
        let ep_scalar = Scalar::from_canonical_bytes(*ep)
            .ok_or(WiredScalarMalformed)?;
        
        debug!("Successfully converted ep to Scalar");
        Ok((xs * ep_scalar + self.k).to_bytes())
    }
}
