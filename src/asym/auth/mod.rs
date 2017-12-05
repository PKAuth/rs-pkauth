
use crypto_abstract::ToAlgorithm;
use crypto_abstract::asym::auth;
use crypto_abstract::asym::auth::{Signature};
pub use crypto_abstract::asym::auth::{Algorithm, PublicKey, PrivateKey, gen};
use serde::ser::{Serialize};
use serde_json;

use internal::{PKAIdentifier, ToIdentifier};
// use internal::{PKAIdentifier,PSF, EncodePSF, DecodePSF};

pub struct PKASigned { //<T> {
    content : Vec<u8>,
    signature : Signature,
    key_identifier : PKAIdentifier,
    algorithm : Algorithm
}

// sign:
// a -> bytestring -> PKASigned
// signContent: 
//      bytestring -> PKASigned
// sign':
// a -> bytestring -> PKASigned -> ByteString
// signContent': 
//      bytestring -> PKASigned -> ByteString

pub fn sign<T>( key : &PrivateKey, o : &T) -> Result<PKASigned, &'static str> where T:Serialize {
    let r = serde_json::to_vec( &o).map_err(|_| "Error generating json.")?;
    sign_content( key, r)
}

pub fn sign_content( key : &PrivateKey, message : Vec<u8>) -> Result<PKASigned, &'static str> {
    let signature = auth::sign( &key, &message).map_err(|_| "Error signing content.")?;
    let identifier = ToIdentifier::to_identifier( key);
    let algorithm = ToAlgorithm::to_algorithm( key);

    Ok( PKASigned {
        content : message,
        signature : signature,
        key_identifier : identifier,
        algorithm : algorithm
    })
}


