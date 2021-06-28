//! # Registration
//!
//! Note: This section is just summarizing the offline registration
//! section of the [internet-draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque),
//! for more information, please read the draft.
//!
//! Both registration and login stages may vary according to the mode as described on the
//! [`crate::envelope::EnvelopeMode`] enum.
//!
//! ### Offline stage
//! This step can occur before client and server connect to each other (hence the stage's name).
//!
//! The client should get one identifier (i.e., email, username, etc) and one password.
//!
//! The server should have one keypair (`server_pri_key`/`server_pub_key`) for use with the AKE protocol,
//! and a `oprf_seed` (byte array). The server can use multiple keypairs and multiple seeds for multiple
//! clients, so long as they are consistent for each client. The server should keep each keypair and seed
//! related to a client stored somewhere, it can't be changed later, so don't lose it!
//!
//! Note: If using "external" mode, the client should provide a keypair (`client_pri_key`/`client_pub_key`) for use
//! with the AKE protocol as well. The keypair may be randomly generated for the account or provided by the
//! calling client. Clients MUST NOT use the same keypair for two different accounts.
//!
//! ### Registration Protocol
//! The registration protocol runs as shown below:
//! ```txt
//!      Client                                         Server
//!     ------------------------------------------------------
//!     (request, blind) = CreateRegistrationRequest(password)
//!                  ----------request--------->
//!
//!    (response, oprf_key) = CreateRegistrationResponse(
//!                                request,
//!                                server_public_key,
//!                                credential_identifier,
//!                                oprf_seed
//!                            )
//!                  <---------response--------
//!
//!     (record, export_key) = FinalizeRequest(
//!                                client_private_key,
//!                                password,
//!                                blind,
//!                                response,
//!                                server_identity,
//!                                client_identity
//!                            )
//!                  ----------record--------->
//!```
//!
//! After `FinalizeRequest`, the server stores the `record` object along with the associated
//! `client_identity` and `credential_identifier`.
//!
//! Note: Once again, the server keypair and the oprf_seed should both be persisted!
//!
//!
//!
//! # Authentication
//!
//! This stage is composed of a concurrent OPRF and key exchange flow. In the end, the client proves its
//! knowledge of the password, and both client and server agree on:
//! - Mutually authenticated shared secret key;
//! - Any optional application information exchange during the handshake.
//!
//! The key exchange (AKE) flow can be seen on the [`crate::ake`] module description.
//!