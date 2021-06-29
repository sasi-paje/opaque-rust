use std::mem::size_of;
use std::io;
use std::ops::Deref;
use rand::{RngCore, CryptoRng};
use rand::rngs::OsRng;
use sha2::Sha512;
use digest::{Digest, BlockInput};
use digest::generic_array::typenum::Unsigned;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

static STR_VOPRF: &[u8] = b"VOPRF06-HashToGroup-";
static STR_VOPRF_FINALIZE: &[u8] = b"VOPRF06-Finalize-";
static MODE_BASE: u8 = 0x00;
static SUITE_ID: usize = 0x0001;

/// Convert "input" into an element of the OPRF group, randomize it by an scalar and return both.
///
/// # Arguments
///
/// * `input`: A user input to be blinded.
///
/// # Returns
///
/// * `blind`: Scalar used to randomize the OPRF element.
/// * `blinded_element`: OPRF element after blind.
pub(crate) fn blind(input: &[u8]) -> io::Result<(Vec<u8>, Scalar, RistrettoPoint)> {
    // Random Scalar (blind = GG.RandomScalar()).
    let mut rng = OsRng::default();
    let blind = nonzero_random_scalar(&mut rng);

    let dst = [STR_VOPRF, &get_context_string(MODE_BASE)].concat();

    // Map To Curve (P = GG.HashToGroup(input)).
    let uniform_bytes = expand_message_xmd(input, &dst, <Sha512 as Digest>::OutputSize::to_usize())?;
    let bits: [u8; 64] = {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&uniform_bytes);
        bytes
    };
    let p = RistrettoPoint::from_uniform_bytes(&bits);

    // Serialize Element (blindedElement = GG.SerializeElement(blind * P)).
    let blinded_element = p * &blind;

    Ok((input.to_vec(), blind, blinded_element))
}

pub(crate) fn evaluate(_private_key: Vec<u8>, _public_key: Vec<u8>, _blinded_element: Vec<u8>) { // ->
    /*
     R = GG.DeserializeElement(blindedElement)
     Z = skS * R
     evaluatedElement = GG.SerializeElement(Z)

     proof = GenerateProof(skS, pkS, blindedElement, evaluatedElement)

     return evaluatedElement, proof
     */
}

pub(crate) fn finalize(_input: Vec<u8>, _blind: Vec<u8>, _element: Vec<u8>) { // -> Vec<u8>
    /*
     unblindedElement = Unblind(blind, evaluatedElement)

     finalizeDST = "VOPRF06-Finalize-" || self.contextString
     hashInput = I2OSP(len(input), 2) || input ||
                 I2OSP(len(unblindedElement), 2) || unblindedElement ||
                 I2OSP(len(finalizeDST), 2) || finalizeDST
     return Hash(hashInput)
     */
}


// ||===============================================================================================
// || Helper Methods ||
// ||===============================================================================================
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

/// Integer to Octet String primitive
fn i2osp(input: usize, length: usize) -> Vec<u8> {
    if length <= size_of::<usize>() {
        return (&input.to_be_bytes()[size_of::<usize>() - length..]).to_vec();
    }

    let mut output = vec![0u8; length];
    output.splice(
        length - std::mem::size_of::<usize>()..length,
        input.to_be_bytes().iter().cloned(),
    );
    output
}

fn xor(x: &[u8], y: &[u8]) -> io::Result<Vec<u8>> {
    if x.len() != y.len() {
        return Err(io::Error::from_raw_os_error(2));
    }

    Ok(x.iter().zip(y).map(|(&x1, &x2)| x1 ^ x2).collect())
}

fn expand_message_xmd(msg: &[u8], dst: &[u8], len_bytes: usize) -> io::Result<Vec<u8>> {
    let b_bytes = <Sha512 as Digest>::OutputSize::to_usize();
    let r_bytes = <Sha512 as BlockInput>::BlockSize::to_usize();

    let ell = (len_bytes / b_bytes + ((len_bytes % b_bytes != 0) as usize));
    if ell > 255 {
        return Err(io::Error::from_raw_os_error(1));
    }

    let dst_prime = [dst, &i2osp(dst.len(), 1)].concat();
    let z_pad = i2osp(0, r_bytes);
    let l_i_b_str = i2osp(len_bytes, 2);
    let msg_prime = [&z_pad, msg, &l_i_b_str, &i2osp(0, 1), &dst_prime].concat();

    let mut b: Vec<Vec<u8>> = vec![Sha512::digest(&msg_prime).to_vec()];

    let mut h = Sha512::new();
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

fn get_context_string(mode: u8) -> Vec<u8> {
    [i2osp(mode as usize, 1), i2osp(SUITE_ID, 2)].concat()
}
