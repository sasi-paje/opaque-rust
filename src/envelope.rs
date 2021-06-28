/// Credentials info that will be encoded inside the Envelope.
pub struct CleartextCredentials {
    /// Encoded server public key for the AKE protocol.
    server_public_key: Vec<u8>,
    /// Typically a domain name, e.g. example.com (defaults to encoded server's public key).
    server_identity: Vec<u8>,
    /// Application-specific value, e.g. email address or account name (defaults to encoded client's public key).
    client_identity: Vec<u8>,
}

impl CleartextCredentials {
    /// Returns a new CleartextCredentials.
    ///
    /// # Arguments
    ///
    /// * `server_pub_key` - The encoded server's public key.
    /// * `client_pub_key` - The encoded client's public key.
    /// * `server_identity` - The optional encoded server's identity.
    /// * `client_identity` - The optional encoded client's identity.
    pub fn new(
        server_pub_key: Vec<u8>,
        client_pub_key: Vec<u8>,
        server_identity: Option<Vec<u8>>,
        client_identity: Option<Vec<u8>>,
    ) -> Self {
        let srv_identity = if let Some(identity) = server_identity { identity } else { server_pub_key.clone() };
        let cli_identity = if let Some(identity) = client_identity { identity } else { client_pub_key };

        CleartextCredentials {
            server_public_key: server_pub_key,
            server_identity: srv_identity,
            client_identity: cli_identity,
        }
    }
}

/// A mode dependent envelope structure. In fact, it's only used on [`EnvelopeMode::External`].
pub struct InnerEnvelope {
    /// Encrypted `client_pri_key`. Authentication of this field is ensured with the `auth_tag` field
    /// in the [`Envelope`] that covers this `InnerEnvelope`.
    credentials: Vec<u8>,
}

pub(crate) enum EnvelopeMode {
    /// Internal mode: In this mode, the client's private and public keys are deterministically derived
    /// from the OPRF output. In this case, there are no [`InnerEnvelope`].
    Internal,
    /// External mode: This mode allows applications to import or generate keys for the
    /// client.  This specification only imports the client's private key and
    /// internally recovers the corresponding public key.  Implementations
    /// are free to import both, in which case the functions
    /// "FinalizeRequest()", "CreateEnvelope()", and "BuildInnerEnvelope()"
    /// must be adapted accordingly.
    External,
}

impl EnvelopeMode {
    /// Create [`InnerEnvelope`].
    ///
    /// The input and output will actually depend on the mode. Please, refer to
    /// [`EnvelopeMode::internal_build_inner_envelope()`] and [`EnvelopeMode::external_build_inner_envelope()`] for more details.
    pub fn build_inner_envelope(
        &self,
        _pwd: String,
        _nonce: Vec<u8>,
        _client_pri_key: Vec<u8>,
    ) { // -> (InnerEnv, Vec<u8>) {
    }

    /// Recover and return the client's private and public keys.
    ///
    /// The input and output will actually depend on the mode. Please, refer to
    /// [`EnvelopeMode::internal_recover_keys()`] and [`EnvelopeMode::external_recover_keys()`] for more details.
    pub fn recover_keys(
        &self,
        _pwd: String,
        _nonce: Vec<u8>,
        _inner_env: InnerEnvelope,
    ) { // -> (Vec<u8>, Vec<u8>) {
    }

    // ||=================================================
    // || Internal Methods ||
    // ||=================================================
    /// Since in internal mode both client's private and public keys are deterministically derived,
    /// there is no need for this method to receive the client_pri_key.
    ///
    /// # Arguments
    ///
    /// * `pwd`: Randomized password.
    /// * `nonce`: A unique nonce.
    ///
    /// # Returns
    ///
    /// * `client_pub_key`: The new generated client's public key.
    ///
    fn internal_build_inner_envelope(_pwd: String, _nonce: Vec<u8>) { // -> Vec<u8> {
        /*
        1. seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nsk)
        2. _, client_public_key = DeriveAuthKeyPair(seed)
        3. Output (nil, client_public_key)
        */
    }

    /// Recovers the client's keypair.
    ///
    /// The internal ```recover_keys``` method won't receive an [`InnerEnvelope`]
    /// (since it doesn't exist).
    ///
    /// # Arguments
    ///
    /// * `pwd`: Randomized password.
    /// * `nonce`: A unique nonce.
    ///
    /// # Returns
    ///
    /// * `client_pri_key`: The encoded client private key.
    /// * `client_pub_key`: The encoded client public key.
    fn internal_recover_keys(_pwd: String, _nonce: Vec<u8>) { // -> (Vec<u8>, Vec<u8>)
        /*
        1. seed = Expand(randomized_pwd, concat(nonce, "PrivateKey"), Nsk)
        2. client_private_key, client_public_key = DeriveAuthKeyPair(seed)
        4. Output (client_private_key, client_public_key)
        */
    }

    /// This methods generates the internal keypair.
    ///
    /// # Arguments
    ///
    /// * `seed`: pseudo-random byte sequence used as a seed.
    ///
    /// # Returns
    ///
    /// * `private_key`: a private key.
    /// * `public_key`: the associated public key.
    fn derive_auth_keypair(_seed: Vec<u8>) { // -> Vec<u8>
        /*
        1. private_key = HashToScalar(seed, dst="OPAQUE-HashToScalar")
        2. public_key = ScalarBaseMult(private_key)
        3. Output (private_key, public_key)

        Note: HashToScalar(msg, dst) is as specified in [I-D.irtf-cfrg-voprf], except that the "dst"
        parameter is "OPAQUE-HashToScalar".
        */
    }

    // ||=================================================
    // || External Methods ||
    // ||=================================================
    /// An encryption key is generated from the hardened OPRF output and used to encrypt the
    /// client's private key, which is then stored encrypted in the [`InnerEnvelope`].  On key
    /// recovery, the client's public key is recovered using the private key.
    ///
    /// Note: The public key can be provided, in which case the "recover_public_key" step can be
    /// avoided. This is just something to think about when it's time to implement.
    ///
    /// # Arguments
    ///
    /// * `pwd`: Randomized password.
    /// * `nonce`: A unique nonce.
    /// * `client_pri_key`: The encoded client private key.
    ///
    /// # Returns
    ///
    /// * `inner_env`: An [`InnerEnvelope`] structure.
    /// * `client_pub_key`: The encoded client public key.
    fn external_build_inner_envelope(_pwd: String, _nonce: Vec<u8>, _client_pri_key: Vec<u8>) { // -> (InnerEnv, Vec<u8>) {
        /*
        1. pseudorandom_pad = Expand(randomized_pwd, concat(nonce, "Pad"), len(client_private_key))
        2. encrypted_creds = xor(client_private_key, pseudorandom_pad)
        3. Create InnerEnvelope inner_env with encrypted_creds
        4. client_public_key = RecoverPublicKey(client_private_key)
        5. Output (inner_env, client_public_key)
        */
    }

    /// Recovers the client's keypair.
    ///
    /// # Arguments
    ///
    /// * `pwd`: Randomized password.
    /// * `nonce`: A unique nonce.
    /// * `inner_env`: An [`InnerEnvelope`].
    ///
    /// # Returns
    ///
    /// * `client_pri_key`: The encoded client private key.
    /// * `client_pub_key`: The encoded client public key.
    fn external_recover_keys(_pwd: String, _nonce: Vec<u8>) { // -> (Vec<u8>, Vec<u8>)
        /*
        1. encrypted_creds = inner_env.encrypted_creds
        2. pseudorandom_pad = Expand(randomized_pwd, concat(nonce, "Pad"), len(encrypted_creds))
        3. client_private_key = xor(encrypted_creds, pseudorandom_pad)
        4. client_public_key = RecoverPublicKey(client_private_key)
        5. Output (client_private_key, client_public_key)
        */
    }
}


/// Structure to manage client credentials, it holds information about its format
/// and content for the client to obtain its authentication material. The envelope can be one of two
/// modes: "internal" and "external", these modes will determine the structure of the "InnerEnvelope" struct.
///
/// The envelope struct will be created at the registration stage.
///
/// Note: the serialized envelope size varies based on the mode.
pub struct Envelope {
    /// Unique nonce used to protect the Envelope.
    nonce: Vec<u8>,
    /// A mode dependent structure. In internal mode it will be ```None```.
    inner_env: Option<InnerEnvelope>,
    /// Authentication tag protecting the contents of the envelope, covering the envelope
    /// ```nonce```, [`InnerEnvelope`], and [`CleartextCredentials`].
    auth_tag: Vec<u8>,
}

impl Envelope {
    /// Clients create an "Envelope" at registration.
    ///
    /// # Arguments
    ///
    /// * `pwd`: Randomized password.
    /// * `server_pub_key`: The encoded server's public key.
    /// * `client_private`: The encoded client's private key.
    /// * `server_identity` - The optional encoded server's identity.
    /// * `client_identity` - The optional encoded client's identity.
    ///
    /// For the "internal" mode, implementations can choose to leave out the client_private_key parameter, as it
    /// is not used.
    ///
    /// For the "external" mode, implementations are free to additionally provide "client_pub_key" to this function.
    /// With this, public key not need to be recovered by ```BuildInnerEnvelope()``` and that function should be adapted
    /// accordingly.
    ///
    /// # Returns
    ///
    /// * ```envelope```: The envelope itself.
    /// * ```client_pub_key```: The client's public key (when not in "external" mode).
    /// * ```masking_key```: A key used by the server to encrypt the envelope during login.
    /// * ```export_key```: An additional client key.
    pub fn create(
        _pwd: String,
        _server_pub_key: Vec<u8>,
        _client_private_key: Vec<u8>,
        _server_identity: Option<Vec<String>>,
        _client_identity: Option<Vec<String>>,
    ) {  // -> (Self, Vec<u8>, Vec<u8>, Vec<u8>) {
        /*
        1. envelope_nonce = random(Nn)
        2. auth_key = Expand(randomized_pwd, concat(envelope_nonce, "AuthKey"), Nh)
        3. export_key = Expand(randomized_pwd, concat(envelope_nonce, "ExportKey"), Nh)
        4. masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
        5. inner_env, client_public_key = BuildInnerEnvelope(randomized_pwd, envelope_nonce, client_private_key)
        6. cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key, server_identity, client_identity)
        7. auth_tag = MAC(auth_key, concat(envelope_nonce, inner_env, cleartext_creds))
        8. Create Envelope envelope with (envelope_nonce, inner_env, auth_tag)
        9. Output (envelope, client_public_key, masking_key, export_key)
        */
    }

    /// Clients recovers their Envelope during authentication.
    ///
    /// # Arguments
    ///
    /// * `mode`: What mode (internal/external) is being used.
    /// * `pwd`: Randomized password.
    /// * `server_pub_key`: The encoded server's public key.
    /// * `server_identity` - The optional encoded server's identity.
    /// * `client_identity` - The optional encoded client's identity.
    ///
    /// # Returns
    ///
    /// * ```client_pri_key```: The encoded client private key.
    /// * ```export_key```: An additional client key.
    ///
    /// # Exceptions
    ///
    /// * ```EnvelopeRecoveryError```: When the envelope fails to be recovered.
    pub fn recover(
        &self,
        _mode: EnvelopeMode,
        _pwd: String,
        _server_pub_key: Vec<u8>,
        _server_identity: Option<Vec<String>>,
        _client_identity: Option<Vec<String>>,
    ) { // -> (Vec<u8>, Vec<u8>)
        /*
        1. auth_key = Expand(randomized_pwd, concat(envelope.nonce, "AuthKey"), Nh)
        2. export_key = Expand(randomized_pwd, concat(envelope.nonce, "ExportKey", Nh)
        3. (client_private_key, client_public_key) =
            RecoverKeys(randomized_pwd, envelope.nonce, envelope.inner_env)
        4. cleartext_creds = CreateCleartextCredentials(server_public_key,
                              client_public_key, server_identity, client_identity)
        5. expected_tag = MAC(auth_key, concat(envelope.nonce, inner_env, cleartext_creds))
        6. If !ct_equal(envelope.auth_tag, expected_tag),
             raise EnvelopeRecoveryError
        7. Output (client_private_key, export_key)
        */
    }
}
