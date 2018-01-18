#![deny(warnings)]

extern crate base64;
extern crate boolinator;
extern crate crypto_abstract;
extern crate ring;
extern crate ripemd160;
extern crate rust_base58;
extern crate serde;
// #[macro_use]
// extern crate serde_derive;
extern crate serde_json;

/// Module for internal use. You probably don't want this.
pub mod internal; 

/// Asymmetric cryptography.
pub mod asym;

/// Symmetric cryptography.
pub mod sym;

// Re-exports.
pub use crypto_abstract::{ToAlgorithm, ToPublicKey};
pub use internal::{AlgorithmId, ToIdentifier, PKAJ}; //, EncodePSF, DecodePSF, serialize_psf, deserialize_psf, PKAJ}; // decode_psf', deserializePSF' extractDomainName

// #[cfg(test)]
// mod tests {
//     #[test]
//     fn it_works() {
//         assert_eq!(2 + 2, 4);
//     }
// }
