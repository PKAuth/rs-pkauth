// #![feature(plugin)]
// #![plugin(serde_macros)]

use crypto_abstract::ToAlgorithm;
use crypto_abstract::sym::enc;
pub use crypto_abstract::sym::enc::{gen, Key, Algorithm};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde::de::{Visitor, MapAccess, Deserialize, Deserializer};
use serde_json;
use std::fmt;

use internal::{PKAIdentifier,PSF, EncodePSF};
use internal::*;
use internal::sym::enc::*;

// #[derive(Serialize, Deserialize)]
pub struct PKASymEncrypted {
    ciphertext : PSF<enc::CipherText>,
    identifier : PKAIdentifier,
    algorithm : Algorithm
}

impl Serialize for PKASymEncrypted {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let mut s = serializer.serialize_struct("PKASymEncrypted", 3)?;
        s.serialize_field( "ciphertext", &self.ciphertext)?;
        s.serialize_field( "identifier", &self.identifier)?;
        let a = AlgorithmId::to_algorithm_id( &self.algorithm);
        s.serialize_field( "algorithm", a)?;

        s.end()
    }
}

// impl Serialize for PKASymEncrypted {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
//         let mut s = serializer.serialize_struct("PKASymEncrypted", 3)?;
//         s.serialize_field( "ciphertext", "TODO");
//         s.serialize_field( "identifier", "TODO");
//         s.serialize_field( "algorithm", "TODO");
//         s.end()
//     }
// }
// 
// impl<'d> Deserialize<'d> for PKASymEncrypted {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'d> {
// 
//         #[derive(Deserialize)]
//         #[serde(field_identifier, rename_all = "lowercase")]
//         enum Field {Ciphertext, Identifier, Algorithm};
// 
//         struct PKASEVisitor;
// 
//         impl Visitor<'d> for PKASEVisitor {
//             type Value = PKASymEncrypted;
// 
//             fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                 formatter.write_str( "PKAuth encoded symmetrically encrypted content");
//             }
// 
//             fn visit_map<V>(self, mut map: V) -> Result<PKASymEncrypted, V::Error> where V: MapAccess<'d> {
//                 let mut ciphertext = None;
//                 let mut identifier = None;
//                 let mut algorithm = None;
// 
//                 while let Some(key) = map.next_key()? {
//                     unimplemented!();
//                 }
// 
//                 unimplemented!();
//             }
//         }
// 
//         const FIELDS: &'static [&'static str] = &["ciphertext","identifier","algorithm"];
//         deserializer.deserialize_struct("PKASymEncrypted", FIELDS, PKASEVisitor)
//     }
// 
// }


// encrypt:
// a -> bytestring -> PKAEncrypted
// encryptContent:
//      bytestring -> PKAEncrypted
// encrypt':
// a -> bytestring -> PKAEncrypted -> ByteString
// encryptContent':
//      bytestring -> PKAEncrypted -> ByteString

pub fn encrypt_content( rng : &SystemRandom, key : Key, msg : Vec<u8>) -> Result<PKASymEncrypted, Unspecified> {
    let ciphertext = enc::encrypt( &rng, &key, msg)?;

    let i = ToIdentifier::to_identifier( &key);
    let a = ToAlgorithm::to_algorithm( &key);

    Ok( PKASymEncrypted{ ciphertext : EncodePSF::encode_psf( &ciphertext), identifier : i, algorithm : a})
}

pub fn encrypt_content_bs( rng : &SystemRandom, key : Key, msg : Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let encrypted = encrypt_content( rng, key, msg).map_err(|_| "Error encrypting content.")?;

    serde_json::to_vec( &encrypted).map_err(|_| "Error converting encrypted content to json.")
}

