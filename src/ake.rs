//! AKE protocol - 3DH
//!
//! The protocol consists of three messages sent between client and server, and runs as follows:
//!
//! The client inputs:
//! - password: client's password.
//! - client_identity: client identity as defined during registration.
//!
//! The client receives:
//! - export_key: a key only available to the client that may be used for additional application-specific purposes.
//! - session_secret: a secret used to identify the user's session. (something token-like)
//!
//! Note: export_key MUST NOT be used in any way before the protocol completes.
//!
//! The server inputs:
//! - server_pri_key: server private key.
//! - server_pub_key: server public key.
//! - server_identity: server identity as defined during registration.
//! - record: [`crate::messages::registration::RegistrationUpload`] stored during registration.
//! - credential_identifier: client credential identifier.
//! - oprf_seed: seed used to derive per-client OPRF keys.
//!
//! The server receives:
//! - session_secret: a secret matching that one of the client.
//!
//! The protocol runs as shown below:
//! ```txt
//!     Client                                         Server
//!     ------------------------------------------------------
//!      ke1 = ClientInit(client_identity, password)
//!                  -----------ke1----------->
//!
//!
//!             ke2 = ServerInit(
//!                         server_identity,
//!                         server_private_key,
//!                         server_public_key,
//!                         record,
//!                         credential_identifier,
//!                         oprf_seed,
//!                         ke1
//!                   )
//!                  <----------ke2------------
//!
//!
//!      (ke3, session_key, export_key) = ClientFinish(
//!                                             password,
//!                                             client_identity,
//!                                             server_identity,
//!                                             ke2
//!                                       )
//!                  -----------ke3----------->
//!
//!                  session_key = ServerFinish(ke3)
//! ```
//!
//! `ke1`, `ke2` and `ke3` are the three protocol messages sent between client and server.
//!
//! `session_key` and `export_key` are outputs to be consumed by applications.
//!
//! Both `ClientFinish` and `ServerFinish` return an error if authentication failed. In this case,
//! neither client nor server MUST NOT use any outputs from the protocol, such as `session_key` or `export_key`.
//!
//! Both `ClientInit` and `ServerInit` implicitly return internal state objects `client_state` ([`ClientState`]) and `server_state` ([`ServerState`]).
//!
//! Before the execution of any function related to client-server communication, both client and server MUST agree
//! on a configuration (more on that later).

use crate::messages::ake::{KE1, KE2, KE3};
use crate::messages::credential::{CredentialRequest, CredentialResponse};
use crate::messages::registration::RegistrationUpload;

struct ClientState {
    blind: Vec<u8>,
    client_secret: Vec<u8>,
    ke1: KE1,
}

impl ClientState {
    /// Init client events
    ///
    /// # Arguments
    ///
    /// * `pwd`: client's password.
    /// * `client_identity`: optional encoded client identity.
    ///
    /// # Returns
    ///
    /// * `ke1`: A [`KE1`] structure.
    /// * `blind`: A OPRF blinding scalar.
    /// * `client_secret`: The client's Diffie-Hellman secret share for the session.
    pub fn client_init(
        &self,
        _pwd: String,
        _client_identity: Option<Vec<String>>,
    ) { // -> (KE1, Vec<u8>, Vec<u8>)
        /*
        1. request, blind = CreateCredentialRequest(password)
        2. state.blind = blind
        3. ke1 = Start(request)
        4. Output ke1
        */
    }

    /// Finish client events
    ///
    /// # Arguments
    ///
    /// * `pwd`: client's password.
    /// * `ke1`: a [`KE1`] structure.
    /// * `ke2`: a [`KE2`] structure.
    /// * `client_identity`: optional encoded client_identity.
    /// * `server_identity`: optional encoded server_identity.
    ///
    /// # Returns
    ///
    /// * `ke3`: KE3 message structure
    /// * `session_key`: session's shared secret
    pub fn client_finish(
        &self,
        _pwd: String,
        _ke1: KE1,
        _ke2: KE2,
        _client_identity: Option<Vec<String>>,
        _server_identity: Option<Vec<String>>,
    ) { // -> (KE3, Vec<u8>)
        /*
        1. (client_private_key, server_public_key, export_key) = RecoverCredentials(password, state.blind, ke2.CredentialResponse, server_identity, client_identity)
        2. (ke3, session_key) = ClientFinalize(client_identity, client_private_key, server_identity, server_public_key, ke1, ke2)
        3. Output (ke3, session_key)
        */
    }

    /// Start client requests
    ///
    /// # Arguments
    ///
    /// * `credential_request`: a [`CredentialRequest`] structure.
    ///
    /// # Returns
    ///
    /// * `ke1`: a [`KE1`] structure.
    ///
    fn start(&self, _credential_request: CredentialRequest) { // -> KE1
        /*
        1. client_nonce = random(Nn)
        2. client_secret, client_keyshare = GenerateAuthKeyPair()
        3. Create KE1 ke1 with (credential_request, client_nonce, client_keyshare)
        4. state.client_secret = client_secret
        5. Output (ke1, client_secret)
        */
    }

    /// Finish client requests
    ///
    /// # Arguments
    ///
    /// * `client_pri_key`: Client's private key.
    /// * `server_pub_key`: Server's public key.
    /// * `ke2`: a KE2 message structure.
    /// * `client_identity`: Optional client identity.
    /// * `server_identity`: Optional server identity.
    ///
    /// # Returns
    ///
    /// * `ke3`: a KE3 structure.
    /// * `session_key`: the shared session secret.
    fn finalize(
        &self,
        _client_pri_key: Vec<u8>,
        _server_pub_key: Vec<u8>,
        _ke2: KE2,
        _client_identity: Option<String>,
        _server_identity: Option<String>,
    ) { // -> (KE3, Vec<u8>)
        /*
        1. ikm = TripleDHIKM(state.client_secret, ke2.server_keyshare, state.client_secret, server_public_key, client_private_key, ke2.server_keyshare)
        2. preamble = Preamble(client_identity, state.ke1, server_identity, ke2.inner_ke2)
        3. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
        4. expected_server_mac = MAC(Km2, Hash(preamble))
        5. If !ct_equal(ke2.server_mac, expected_server_mac),
            raise HandshakeError
        6. client_mac = MAC(Km3, Hash(concat(preamble, expected_server_mac))
        7. Create KE3 ke3 with client_mac
        8. Output (ke3, session_key)
        */
    }
}

struct ServerState {
    expected_client_mac: Vec<u8>,
    session_key: Vec<u8>,
}

impl ServerState {
    /// Init server response
    ///
    /// # Arguments
    ///
    /// * `server_pri_key`: Server's private key.
    /// * `server_pub_key`: Server's public key.
    /// * `record`: A [`RegistrationUpload`] structure.
    /// * `identifier`: The user's identifier.
    /// * `oprf_seed`: The server-side seed.
    /// * `ke1`: A [`KE1`] structure.
    /// * `server_identity`: Optional server identity.
    ///
    /// # Returns
    ///
    /// * `ke2`: A [`KE2`] structure.
    pub fn server_init(
        &self,
        _server_pri_key: Vec<u8>,
        _server_pub_key: Vec<u8>,
        _record: RegistrationUpload,
        _identifier: String,
        _oprf_seed: Vec<u8>,
        _ke1: KE1,
        _server_identity: Option<String>,
    ) { // -> KE2
        /*
        1. response = CreateCredentialResponse(ke1.request, server_public_key, record, credential_identifier, oprf_seed)
        2. ke2 = Response(server_identity, server_private_key, client_identity, record.client_public_key, ke1, response)
        3. Output ke2
        */
    }

    /// Finish server response
    ///
    /// # Arguments
    ///
    /// * `ke3`: A [`KE3`] structure.
    ///
    /// # Returns
    ///
    /// * `session_key`: Shared session secret.
    ///
    pub fn server_finish(&self, _ke3: KE3) { // -> Vec<u8>
        /*
         1. if !ct_equal(ke3.client_mac, state.expected_client_mac):
                raise HandshakeError
         2. Output state.session_key
         */
    }

    /// Build response message.
    ///
    /// # Arguments
    ///
    /// * `server_pub_key`: Server's public key.
    /// * `server_pri_key`: Server's private key.
    /// * `client_pub_key`: Client's public key.
    /// * `client_pri_key`: Client's private key.
    /// * `ke1`: A [`KE1`] structure.
    /// * `credential_response`: A [`CredentialResponse`] structure.
    /// * `server_identity`: Optional server identity.
    /// * `client_identity`: Optional client identity.
    ///
    /// # Returns
    ///
    /// * `ke2`: A [`KE2`] structure.
    fn response(
        &self,
        _server_pub_key: Vec<u8>,
        _server_pri_key: Vec<u8>,
        _client_pub_key: Vec<u8>,
        _client_pri_key: Vec<u8>,
        _ke1: KE1,
        _credential_response: CredentialResponse,
        _server_identity: Option<String>,
        _client_identity: Option<String>,
    ) { // -> KE2
        /*
        1. server_nonce = random(Nn)
        2. server_secret, server_keyshare = GenerateAuthKeyPair()
        3. Create inner_ke2 ike2 with (credential_response, server_nonce, server_keyshare)
        4. preamble = Preamble(client_identity, ke1, server_identity, ike2)
        5. ikm = TripleDHIKM(server_secret, ke1.client_keyshare, server_private_key, ke1.client_keyshare, server_secret, client_public_key)
        6. Km2, Km3, session_key = DeriveKeys(ikm, preamble)
        7. server_mac = MAC(Km2, Hash(preamble))
        8. expected_client_mac = MAC(Km3, Hash(concat(preamble, server_mac))
        9. Populate state with ServerState(expected_client_mac, session_key)
        10. Create KE2 ke2 with (ike2, server_mac)
        11. Output ke2
        */
    }
}
