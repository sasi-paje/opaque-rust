use crate::envelope::Envelope;

pub struct RegistrationRequest {
    /// Serialized OPRF group element.
    data: Vec<u8>,
}

impl RegistrationRequest {
    /// Creates a new [`RegistrationRequest`];
    ///
    /// # Arguments
    ///
    /// * `pwd`: Client's password.
    ///
    /// # Returns
    ///
    /// * `request`: RegistrationRequest structure.
    /// * `blind`: An OPRF scalar.
    ///
    pub fn create_registration_request(_pwd: String) { // -> (Self, ) {
        /*
        1. (blind, M) = Blind(password)
        2. Create RegistrationRequest request with M
        3. Output (request, blind)
        */
    }
}

pub struct RegistrationResponse {
    /// Serialized OPRF group element.
    data: Vec<u8>,
    /// Server's encoded public key that will be used for the online authenticated key exchange stage.
    server_pub_key: Vec<u8>,
}

impl RegistrationResponse {
    /// Creates a new [`RegistrationResponse`];
    ///
    /// # Arguments
    ///
    /// * `request`: A RegistrationRequest structure;
    /// * `server_pub_key`: Server's public key;
    /// * `identifier`: Client's credential identifier;
    /// * `oprf_seed`: Server-side seed;
    ///
    /// # Returns
    ///
    /// * `response`: RegistrationResponse structure.
    /// * `oprf_key`: the per-client OPRF key known only to the server.
    ///
    pub fn create_registration_response(
        _request: RegistrationRequest,
        _server_pub_key: Vec<u8>,
        _identifier: String,
        _oprf_seed: Vec<u8>,
    ) { // -> (Self, )
        /*
        1. ikm = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
        2. (oprf_key, _) = DeriveKeyPair(ikm)
        3. Z = Evaluate(oprf_key, request.data)
        4. Create RegistrationResponse response with (Z, server_public_key)
        5. Output (response, oprf_key)
        */
    }
}

pub struct RegistrationUpload {
    /// Client's encoded public key.
    client_pub_key: Vec<u8>,
    /// A key used by the server to preserve confidentiality of the envelope during login.
    masking_key: Vec<u8>,
    /// Client's [`crate::envelope::Envelope`] structure.
    envelope: Envelope,
}

impl RegistrationUpload {
    /// To create the user record used for further authentication, the client
    /// executes the following function. Depending on the mode, implementations are free to leave out the
    /// "client_private_key" parameter ("internal" mode), or to additionally
    /// include "client_public_key" ("external" mode).
    ///
    /// # Arguments
    ///
    /// * `pwd`: Client's password.
    /// * `blind`: The OPRF scalar value used for blinding.
    /// * `response`: A [`RegistrationResponse`] structure.
    /// * `client_pri_key`: Client's private key (only in non-internal modes).
    /// * `client_pub_key`: Client's public key (only in external mode).
    /// * `server_identity`: The optional encoded server identity.
    /// * `client_identity`: The optional encoded client identity.
    ///
    /// # Returns
    ///
    /// * `record`: A [`RegistrationUpload`] structure.
    /// * `export_key`: An additional client key.
    pub fn finalize_request(
        _pwd: String,
        _blind: Vec<u8>, // I guess it's bytes??
        _response: RegistrationResponse,
        _client_pri_key: Option<Vec<u8>>,
        _client_pub_key: Option<Vec<u8>>,
        _server_identity: Option<String>,
        _client_identity: Option<String>,
    ) { // -> (Self, Vec<u8)
        /*
        1. y = Finalize(password, blind, response.data)
        2. randomized_pwd = Extract("", Harden(y, params))
        3. (envelope, client_public_key, masking_key, export_key) = CreateEnvelope(randomized_pwd, response.server_public_key, client_private_key, server_identity, client_identity)
        4. Create RegistrationUpload record with (client_public_key, masking_key, envelope)
        5. Output (record, export_key)
         */
    }
}
