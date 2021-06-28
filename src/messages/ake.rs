use crate::messages::credential::{CredentialRequest, CredentialResponse};


/// Structure sent by the client to the server at the beginning of the AKE protocol.
pub struct KE1 {
    /// A [`CredentialRequest`] created using [`CredentialRequest::create_credential_request`].
    request: CredentialRequest,
    /// A fresh randomly generated nonce.
    client_nonce: Vec<u8>,
    /// Client ephemeral key shared.
    client_keyshare: Vec<u8>,
}

/// Used by KE2
struct InnerKE2 {
    /// A [`CredentialResponse`] created using [`CredentialResponse::create_credential_response`].
    response: CredentialResponse,
    /// A fresh randomly generated nonce.
    server_nonce: Vec<u8>,
    /// Server ephemeral key share of fixed size.
    server_keyshare: Vec<u8>,
}

pub struct KE2 {
    /// A [`InnerKE2`] stucture.
    inner_ke2: InnerKE2,
    /// An authentication tag computed over the handshake transcript.
    server_mac: Vec<u8>,
}

pub struct KE3 {
    /// An authentication tag computed over the handshake transcript.
    client_mac: Vec<u8>,
}