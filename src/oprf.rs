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
pub(crate) fn blind(_input: Vec<u8>) { // -> (Scalar, Vec<u8>)
    /*
     blind = GG.RandomScalar()
     P = GG.HashToGroup(input)
     blindedElement = GG.SerializeElement(blind * P)

     return blind, blindedElement
     */
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
