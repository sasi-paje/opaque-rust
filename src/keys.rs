use std::io;

use crate::hash::{Hash, HashSizing};
use crate::group::Scalar;

pub struct KeyPair {
    pub_k:
    pri_k:
}

pub enum Keys {
    Public(v)
}

pub(crate) fn oprf_key_from_seed(oprf_seed: &[u8], identifier: &[u8]) -> io::Result<Scalar> {
    let mut oprf_key_bytes = vec![0u8; <PrivateKey as SizedBytes>::Len::to_usize()];

    Hkdf::<D>::from_prk(oprf_seed)
        .map_err(|_| InternalPakeError::HkdfError)?
        .expand(
            &[credential_identifier, STR_OPRF_KEY].concat(),
            &mut oprf_key_bytes,
        )
        .map_err(|_| InternalPakeError::HkdfError)?;
    G::hash_to_scalar::<D>(&oprf_key_bytes[..], b"")
}