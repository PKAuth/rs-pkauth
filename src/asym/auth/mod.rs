
use boolinator::Boolinator;
use crypto_abstract::ToAlgorithm;
use crypto_abstract::asym::auth;
pub use crypto_abstract::asym::auth::{Algorithm, PublicKey, PrivateKey, gen};
use serde::de;
use serde::de::{MapAccess, Visitor, Deserializer, Deserialize, DeserializeOwned};
use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde_json;
use std::fmt;

use internal::{AlgorithmId, serialize_base64url, serialize_psf, deserialize_base64url, deserialize_psf};
// use internal::{ToIdentifier, PKAIdentifier,PSF, EncodePSF, DecodePSF};

pub struct PKASigned { //<T> {
    content : Vec<u8>, // JP: Base64 newtype wrapper??
    signature : auth::Signature,
    // identifier : PKAIdentifier
}

impl ToAlgorithm for PKASigned {
    type Algorithm = Algorithm;

    fn to_algorithm( &self) -> Self::Algorithm {
        ToAlgorithm::to_algorithm( &self.signature)
    }
}

impl Serialize for PKASigned {
    fn serialize<S>( &self, serializer: S) -> Result<S::Ok,S::Error> where S : Serializer {
        let mut s = serializer.serialize_struct("PKASigned", 4)?;

        s.serialize_field( "content", &serialize_base64url( &self.content))?;
        s.serialize_field( "signature", &serialize_psf( &self.signature))?;
        // s.serialize_field( "identifier", &self.identifier)?;
        s.serialize_field( "algorithm", &AlgorithmId::to_algorithm_id( &ToAlgorithm::to_algorithm( self)))?;

        s.end()
    }
}

impl<'d> Deserialize<'d> for PKASigned {
    fn deserialize<D>( deserializer : D) -> Result<PKASigned, D::Error> where D : Deserializer<'d> {

        struct V;

        const FIELDS : &'static [&'static str] = &["content", "signature", "algorithm"]; // , "identifier"

        impl<'d> Visitor<'d> for V {
            type Value = PKASigned;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("JSON PKASigned")
            }

            fn visit_map<U>( self, mut map : U) -> Result<PKASigned, U::Error> where U : MapAccess<'d> {
                let mut content = None;
                let mut signature = None;
                // let mut identifier = None;
                let mut algorithm = None;

                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "content" => {
                            content.is_none().ok_or( de::Error::duplicate_field("content"))?;
                            content = Some( map.next_value()?);
                        }
                        "signature" => {
                            signature.is_none().ok_or( de::Error::duplicate_field("signature"))?;
                            signature = Some( map.next_value()?);
                        }
                        // "identifier" => {
                        //     identifier.is_none().ok_or( de::Error::duplicate_field("identifier"))?;
                        //     identifier = Some( map.next_value()?);
                        // }
                        "algorithm" => {
                            algorithm.is_none().ok_or( de::Error::duplicate_field("algorithm"))?;
                            algorithm = Some( map.next_value()?);
                        }
                        _k => {
                            // Skip unknown fields.
                            // Err(de::Error::unknown_field(k, FIELDS))?;
                        }
                    }
                }

                let content : String = content.ok_or_else(|| de::Error::missing_field("content"))?;
                let signature : String = signature.ok_or_else(|| de::Error::missing_field("signature"))?;
                // let identifier : String = identifier.ok_or_else(|| de::Error::missing_field("identifier"))?;
                let algorithm : String = algorithm.ok_or_else(|| de::Error::missing_field("algorithm"))?;

                let algorithm = AlgorithmId::from_algorithm_id( &algorithm).ok_or( de::Error::custom( "invalid algorithm identifier"))?;
                let signature = deserialize_psf( &algorithm, &signature).map_err(de::Error::custom)?;
                let content = deserialize_base64url( &content).map_err(de::Error::custom)?;

                Ok( PKASigned{content : content, signature : signature}) // , identifier : identifier
            }
        }


        deserializer.deserialize_struct( "PKASigned", FIELDS, V)
    }
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

pub fn verify<T>( key : &PublicKey, signed : PKASigned ) -> Result <T,&'static str> where T : DeserializeOwned {
    let bs = verify_content( &key, signed)?;
    serde_json::from_slice( &bs).map_err(|_| "Invalid json encoding.")
}

pub fn sign_content( key : &PrivateKey, message : Vec<u8>) -> Result<PKASigned, &'static str> {
    let signature = auth::sign( &key, &message).map_err(|_| "Error signing content.")?;
    // let identifier = ToIdentifier::to_identifier( key);

    Ok( PKASigned {
        content : message,
        signature : signature,
        // identifier : identifier,
    })
}

// JP: We could return unit instead of the vec, but I think this is a better API.
pub fn verify_content( key : &PublicKey, signed : PKASigned) -> Result<Vec<u8>, &'static str> {
    // Check that the algorithm matches.
    let alg = ToAlgorithm::to_algorithm( &signed.signature);
    (ToAlgorithm::to_algorithm( key) == alg).ok_or("Algorithms do not match.")?;

    // // Check that the identifier matches.
    // (ToIdentifier::to_identifier( key) == signed.identifier).ok_or("Key identifiers do not match.")?;

    // Verify content.
    auth::verify( key, &signed.content, &signed.signature).ok_or("Invalid signature.")?;

    Ok( signed.content)
}

pub fn sign_bs<T>( key : &PrivateKey, o : &T) -> Result<Vec<u8>, &'static str> where T:Serialize {
    let v = serde_json::to_vec( &o).map_err(|_| "Error generating json.")?;
    sign_content_bs( key, v)
}

pub fn verify_bs<T>( key : &PublicKey, signed : Vec<u8>) -> Result<T, &'static str> where T : DeserializeOwned {
    let bs : Vec<u8> = verify_content_bs( key, signed)?;
    serde_json::from_slice( &bs).map_err(|_| "Invalid json encoding.")
}

pub fn sign_content_bs( key :&PrivateKey, message : Vec<u8>) -> Result<Vec<u8>, &'static str> {
	let signed = sign_content( key, message)?;
    serde_json::to_vec( &signed).map_err(|_| "Error generating json.")
}

pub fn verify_content_bs(pub_key : &PublicKey, signed : Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let signed = serde_json::from_slice( &signed).map_err(|_| "Invalid encoding.")?;
    verify_content( pub_key, signed)
}

