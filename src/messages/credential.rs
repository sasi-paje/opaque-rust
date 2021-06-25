use crate::messages::registration::RegistrationUpload;

struct CredentialRequest {
    /// Serialized OPRF group element.
    data: Vec<u8>,
}

impl CredentialRequest {
    /// [USED BY THE CLIENT]
    ///
    /// Create a new [`CredentialRequest`] struct.
    ///
    /// # Arguments
    ///
    /// * `pwd`: Client's password.
    ///
    /// # Return
    ///
    /// * `request`: CredentialRequest struct.
    /// * `blind`: an OPRF scalar.
    pub fn create_credential_request(_pwd: String) { // -> (Self, )
        /*
        1. (blind, M) = Blind(password)
        2. Create CredentialRequest request with M
        3. Output (request, blind)
        */
    }
}

struct CredentialResponse {
    /// Serialized OPRF group element.
    data: Vec<u8>,
    /// A nonce used for the confidentiality of the masked_response field.
    masking_nonce: Vec<u8>,
    /// An encrypted form of the server's public key and client's [`crate::envelope::Envelope`] structure.
    masked_response: Vec<u8>,
}

impl CredentialResponse {
    /// [USED BY THE SERVER]
    ///
    /// If a client's record exists with the corresponding identifier, call this function normally.
    ///
    /// If a client's record does not exist, call this function passing a record configured as:
    /// - record.masking_key: random byte array;
    /// - record.envelope: random byte array consisting only of zeros.
    ///
    /// # Arguments
    ///
    /// * `request`: [`CredentialRequest`] structure.
    /// * `server_pub_key`: Server's public key.
    /// * `record`: [`RegistrationUpload`] structure (output of registration).
    /// * `identifier`: user's identifier.
    /// * `oprf_seed`: the server side seed.
    ///
    /// # Return
    ///
    /// * `response`: [`CredentialResponse`] structure.
    pub fn create_credential_response(
        _request: CredentialRequest,
        _server_pub_key: Vec<u8>,
        _record: RegistrationUpload,
        _identifier: String,
        _oprf_seed: Vec<u8>
    ) { // -> Self
        /*
        1. ikm = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
        2. (oprf_key, _) = DeriveKeyPair(ikm)
        3. Z = Evaluate(oprf_key, request.data)
        4. masking_nonce = random(Nn)
        5. credential_response_pad = Expand(record.masking_key, concat(masking_nonce, "CredentialResponsePad"), Npk + Ne)
        6. masked_response = xor(credential_response_pad, concat(server_public_key, record.envelope))
        7. Create CredentialResponse response with (Z, masking_nonce, masked_response)
        8. Output response
        */
    }

    /// [USED BY THE CLIENT]
    ///
    /// # Arguments
    ///
    /// * `pwd`: Client's password.
    /// * `blind`: OPRF scalar value.
    /// * `server_identity`: Optional server identity.
    /// * `client_identity`: Optional client identity.
    ///
    /// # Return
    ///
    /// * `client_pri_key`: Client's private key.
    /// * `server_pub_key`: Server's public key.
    /// * `export_key`: An additional client key.
    ///
    pub fn recover_credentials(
        &self,
        _pwd: String,
        _blind: Vec<u8>,
        _server_identity: Option<String>,
        _client_identity: Option<String>,
    ) { // -> (Vec<u8>, Vec<u8>, Vec<u8>)
        /*
        1. y = Finalize(password, blind, response.data)
        2. randomized_pwd = Extract("", Harden(y, params))
        3. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
        4. credential_response_pad = Expand(masking_key, concat(response.masking_nonce, "CredentialResponsePad"), Npk + Ne)
        5. concat(server_public_key, envelope) = xor(credential_response_pad, response.masked_response)
        6. (client_private_key, export_key) = RecoverEnvelope(randomized_pwd, server_public_key, envelope, server_identity, client_identity)
        7. Output (client_private_key, response.server_public_key, export_key)
        */
    }
}
