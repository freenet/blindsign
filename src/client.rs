//! Client side of the blind signature protocol

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use digest::Digest;
use std::convert::TryInto;
use crate::signature::UnblindedSigData;
use typenum::U64;
use log::debug;
use crate::Error::{WiredRistrettoPointMalformed, WiredScalarMalformed};
use crate::Result;

/// Manages the client steps of the blind signature protocol.
pub struct BlindClient {
    u: Scalar,
    v: Scalar,
    r: RistrettoPoint,
    e: Scalar,
}

impl BlindClient {
    /// Initiates the blind signature process for a given message.
    ///
    /// # Arguments
    ///
    /// * `rp` - The R' value received from the signer.
    /// * `message` - The message to be blindly signed.
    ///
    /// # Type Parameters
    ///
    /// * `H` - The hash algorithm used for generating e.
    ///
    /// # Returns
    ///
    /// * `Ok(([u8; 32], BlindClient))` - The e' value to be sent to the signer, and the BlindClient instance.
    /// * `Err(Error)` - If there's an error in the process.
    pub fn initiate<H, M>(rp: &[u8; 32], message: M) -> Result<([u8; 32], Self)>
    where
        H: Digest<OutputSize = U64> + Default,
        M: AsRef<[u8]>,
    {
        let rp = CompressedRistretto(*rp)
            .decompress()
            .ok_or(WiredRistrettoPointMalformed)?;

        let u = Scalar::from_bytes_mod_order(rand::random());
        let v = Scalar::from_bytes_mod_order(rand::random());

        let r = u * rp + v * RISTRETTO_BASEPOINT_POINT;
        let e = generate_e::<H>(r, message.as_ref());
        let ep = u.invert() * e;

        debug!("Generated ep: {:?}", ep.to_bytes());

        Ok((ep.to_bytes(), BlindClient { u, v, r, e }))
    }

    /// Finalizes the blind signature process.
    ///
    /// # Arguments
    ///
    /// * `sp` - The blinded signature received from the signer.
    ///
    /// # Returns
    ///
    /// * `Ok(UnblindedSigData)` - The unblinded signature data.
    /// * `Err(Error)` - If there's an error in the process.
    pub fn finalize(self, sp: &[u8; 32]) -> Result<UnblindedSigData> {
        debug!("sp bytes: {:?}", sp);
        let sp_scalar = Scalar::from_canonical_bytes(*sp).ok_or_else(|| WiredScalarMalformed)?;
        
        debug!("Successfully converted sp to Scalar");
        debug!("u: {:?}", self.u.to_bytes());
        debug!("v: {:?}", self.v.to_bytes());
        debug!("e: {:?}", self.e.to_bytes());
        debug!("r: {:?}", self.r.compress().to_bytes());
        
        Ok(UnblindedSigData::new(self.e, sp_scalar * self.u + self.v, self.r))
    }
}

/// Generates e = H(R||m)
pub(crate) fn generate_e<H>(r: RistrettoPoint, m: &[u8]) -> Scalar
where
    H: Digest<OutputSize = U64> + Default,
{
    let mut hasher = H::default();
    hasher.update(r.compress().as_bytes());
    hasher.update(m);
    Scalar::from_bytes_mod_order(hasher.finalize()[..32].try_into().unwrap())
}
