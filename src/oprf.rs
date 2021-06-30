use std::io;
use rand::rngs::OsRng;

use crate::group::{CurveGroup, Group, Scalar};
use crate::hash::{Hash, Digest};
use crate::common::{i2osp, i2osp_serialize};

static STR_VOPRF: &[u8] = b"VOPRF06-HashToGroup-";
static STR_VOPRF_FINALIZE: &[u8] = b"VOPRF06-Finalize-";
static MODE_BASE: u8 = 0x00;
static SUITE_ID: usize = 0x0001;

/// Convert "input" into an element of the OPRF group, randomize it by an scalar and return both.
///
/// # Arguments
///
/// * `input`: A user input to be blinded (in our case, the user password).
///
/// # Returns
///
/// * `blind`: Scalar used to randomize the OPRF element.
/// * `blinded_element`: OPRF element after blind.
pub(crate) fn blind(input: &[u8]) -> io::Result<(Vec<u8>, Scalar, Group)> {
    let mut rng = OsRng::default();
    let dst = generate_dst(STR_VOPRF, MODE_BASE);

    // Random Scalar (blind = GG.RandomScalar()).
    let blind = Group::nonzero_random_scalar(&mut rng);

    // P = GG.HashToGroup(input)
    let p = Group::map_to_curve(input, &dst)?;

    // Serialize Element (blindedElement = GG.SerializeElement(blind * P)).
    let blinded_element = p * &blind;

    Ok((input.to_vec(), blind, blinded_element))
}

/// Revert a blinded element to its original value.
fn unblind(blind: &Scalar, element: Group) -> Group {
    element * blind.invert()
}

/// Computes the (V)OPRF evaluation over the client's blinded token, according to the specs on the rfc
/// (https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-06#section-3.4.1.1).
///
/// # Arguments
///
/// * `point`: the serialized element (a ristretto point in our case).
/// * `oprf_key`: a private key (a Scalar in our case).
///
/// # Returns
///
/// * `evaluated_element`: the evaluated value (another ristretto point in our case).
pub(crate) fn evaluate(point: Group, oprf_key: &Scalar) -> Group {
    point * oprf_key
}

/// The client unblinds the server response, verifies the server's proof if verifiability is required,
/// and produces a byte array corresponding to the output of the OPRF protocol.
///
/// # Arguments
///
/// * `input`: A user input to be blinded (in our case, the user password).
/// * `blind`: A random scalar used during the blind method as the blind factor.
/// * `element`: The element that was evaluated.
///
/// # Returns
///
/// * `output`: A byte array used as the OPRF output.
pub(crate) fn finalize(input: &[u8], blind: &Scalar, element: Group) -> Vec<u8> {
    let dst = generate_dst(STR_VOPRF_FINALIZE, MODE_BASE);

    let unblinded_compressed = {
        let unblinded_element = unblind(blind, element);
        unblinded_element.compress()
    };
    let unblinded_bytes = unblinded_compressed.as_bytes();

    let hash_input = [
        i2osp_serialize(input, 2),
        i2osp_serialize(unblinded_bytes, 2),
        i2osp_serialize(&dst, 2),
    ].concat();
    Hash::digest(&hash_input).to_vec()
}

// ||===============================================================================================
// || Helper Methods ||
// ||===============================================================================================
/// Generate Domain Separation Tag
fn generate_dst(domain: &[u8], mode: u8) -> Vec<u8> {
    [domain, &get_context_string(mode)].concat()
}

fn get_context_string(mode: u8) -> Vec<u8> {
    [i2osp(mode as usize, 1), i2osp(SUITE_ID, 2)].concat()
}
