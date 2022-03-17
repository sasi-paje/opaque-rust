use std::io;
use rand::{RngCore, CryptoRng};
use curve25519_dalek::scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

use crate::common::{xor, i2osp};
use crate::hash::{Hash, HashSizing, Digest};

pub type Scalar = scalar::Scalar;
pub type Group = RistrettoPoint;

pub trait CurveGroup {
    fn map_to_curve(input: &[u8], dst: &[u8]) -> io::Result<RistrettoPoint>;
    fn nonzero_random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar;
    fn expand_message_xmd(msg: &[u8], dst: &[u8], len_bytes: usize) -> io::Result<Vec<u8>>;
}

impl CurveGroup for Group {
    fn map_to_curve(input: &[u8], dst: &[u8]) -> io::Result<RistrettoPoint> {
        let uniform_bytes = Self::expand_message_xmd(input, &dst, Hash::output_size_usize())?;
        let bits: [u8; 64] = {
            let mut bytes = [0u8; 64];
            bytes.copy_from_slice(&uniform_bytes);
            bytes
        };
        Ok(RistrettoPoint::from_uniform_bytes(&bits))
    }

    fn nonzero_random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
        loop {
            let mut scalar_bytes = [0u8; 64];
            rng.fill_bytes(&mut scalar_bytes);
            let scalar = Scalar::from_bytes_mod_order_wide(&scalar_bytes);

            if scalar != Scalar::zero() {
                break scalar;
            }
        }
    }

    fn expand_message_xmd(msg: &[u8], dst: &[u8], len_bytes: usize) -> io::Result<Vec<u8>> {
        let b_bytes = Hash::output_size_usize();
        let r_bytes = Hash::block_size_usize();

        let ell = len_bytes / b_bytes + ((len_bytes % b_bytes != 0) as usize);
        if ell > 255 {
            return Err(io::Error::from_raw_os_error(1));
        }

        let dst_prime = [dst, &i2osp(dst.len(), 1)].concat();
        let z_pad = i2osp(0, r_bytes);
        let l_i_b_str = i2osp(len_bytes, 2);
        let msg_prime = [&z_pad, msg, &l_i_b_str, &i2osp(0, 1), &dst_prime].concat();

        let mut b: Vec<Vec<u8>> = vec![Hash::digest(&msg_prime).to_vec()];

        let mut h = Hash::new();
        h.update(&b[0]);
        h.update(&i2osp(1, 1));
        h.update(&dst_prime);
        b.push(h.finalize_reset().to_vec()); // b[1]

        let mut uniform_bytes: Vec<u8> = Vec::new();
        uniform_bytes.extend_from_slice(&b[1]);

        for i in 2..(ell + 1) {
            h.update(xor(&b[0], &b[i - 1])?);
            h.update(&i2osp(i, 1));
            h.update(&dst_prime);
            b.push(h.finalize_reset().to_vec()); // b[i]
            uniform_bytes.extend_from_slice(&b[i]);
        }

        Ok(uniform_bytes[..len_bytes].to_vec())
    }
}