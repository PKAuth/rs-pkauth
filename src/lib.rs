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

mod internal;
pub mod asym;
pub mod sym;

// Re-exports.
pub use crypto_abstract::{ToAlgorithm, ToPublicKey};
pub use internal::{AlgorithmId, ToIdentifier, PKAJ}; //, EncodePSF, DecodePSF, serialize_psf, deserialize_psf, PKAJ}; // decode_psf', deserializePSF' extractDomainName

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
