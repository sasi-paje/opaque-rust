//! # About
//! Implementation of the Opaque protocol in Rust with integration support for wasm, ffi and others. 
//! This implementation is directly in sync with the [draft-irtf-cfrg-opaque](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque).
//! It's also worth to mention the [opaque-ke](https://github.com/novifinancial/opaque-ke) which inspired me to do this;
//! those guys are doing an awesome job but our projects have slightly different objectives to accomplish.
//! The main objective is to build an easy interface with external resources to use Rust's power with another languages and frameworks
//! in order to build secure authentication flows using the Opaque protocol even in no-Rust environments.
//! 
//! Note: since we're trying to keep everything in sync, some breaking changes may occur along the way, but we'll ***try*** to keep the interfaces as
//! consistent as possible in order to start using it out of the box without major problems.
//! 
//! # Opaque Protocol
//! Note: This section is just summarizing the [protocol overview](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque#section-3)
//! section of the internet-draft, for more information, please read the draft.
//! 
//! Opaque is an asymmetric PAKE (aPAKE) protocol in which a client authenticates within a server with password+identifier, but neither
//! the server knows the password nor the client knows what kind of salt the server stores. Opaque is a aPAKE protocol that has been proven
//! to be secure and to have a good performance (at least for a PAKE protocol). There are loads of Opaque variations (even with post-quantum
//! techiniques), maybe in the future they'll be implemented here as well.
//! 
//! Opaque consists of two stage: registration and authenticated key exchange (AKE). Both are described below, and you can check everything in the
//! examples.
//!
//! Note: You can see more information about each stage on the docs for the [`opaque`] mod.
//! 
//! ## Registration Stage
//! In the registration stage, both the client and the server need to input some information: the client needs to input its password+identifier;
//! the server needs some parameters (private key* and other information depending on the variation). 
//! 
//! The client outputs a ```export_key``` that it may use for "application-specific purposes" (i.e. encrypt information to the server).
//! 
//! The server outputs a record corresponding to the client's registration, and it also should store it inside a credential file alongside 
//! other client registrations as needed (i.e. database).
//! 
//! ## Authentication Stage
//! In the authentication stage, again, both the client and the server need to input some informations: the client inputs its password+identifier; the
//! server inputs some parameters and the previously stored credential file for that client.
//! 
//! The client outputs a ```export_key``` matching that one from registration, and a ```session_key``` (which is the primary AKE output).
//! 
//! The server outputs a single value ```session_key``` that matches that of the client.
//! 
//! After that, client and server can use these values as needed.
//! 

pub mod envelope;
pub mod messages;
pub mod opaque;
pub mod ake;

pub fn hello_world() -> String {
    String::from("Hello, world!")
}
