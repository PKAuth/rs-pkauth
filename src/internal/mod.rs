
pub mod asym;
pub mod sym;

use base64;
use ring::digest::{digest, SHA256};
use ripemd160::{Ripemd160, Digest};
use rust_base58::base58::{ToBase58};
// use serde::ser::{Serialize, Serializer};

/// Newtype wrapper for JSON in PKAuth form since we can't create `Serialize` instances due
/// to orphan instances.
pub struct PKAJ<T> {
    pub pkaj : T
}

pub type PKAIdentifier = String;

// JP: Can we revert back to this version of serialize_psf?
// pub fn serialize_psf<S,T>( o : &T, serializer : S) -> Result<S::Ok, S::Error> where S : Serializer, T : EncodePSF {
// pub fn serialize_psf_old<S,T>( o : &T, serializer : S) -> Result<S::Ok, S::Error> where S : Serializer, T : EncodePSF {
//     let s = serialize_psf( o);
//     s.serialize( serializer)
// }

pub fn serialize_psf<T>( o : &T) -> String where T : EncodePSF {
    let content = EncodePSF::encode_psf( o);
    let s = base64::encode_config( &content, base64::URL_SAFE);
    s
}

// JP: How do we return an error (de::Error::custom)?
pub fn deserialize_psf<T>( algorithm : &T::Algorithm, s : &String) -> Result<T,&'static str> where T : DecodePSF {
    let ciphertext = base64::decode_config( &s, base64::URL_SAFE).map_err(|_| "invalid Base64Url encoding")?;
    DecodePSF::decode_psf( algorithm, &ciphertext)
}

pub fn serialize_base64url( bs : &Vec<u8>) -> String {
    base64::encode_config( &bs, base64::URL_SAFE)
}

pub fn deserialize_base64url( s : &String) -> Result<Vec<u8>,&'static str> {
    base64::decode_config( &s, base64::URL_SAFE).map_err(|_| "invalid Base64Url encoding")
}

// impl<T> Serialize for PSF<T> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S:Serializer {
//         serialize_psf( self).serialize( serializer)
//     }
// }
// 
// impl<'d, T> Deserialize<'d> for PSF<T> {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D:Deserializer<'d> {
//         let s = Deserialize::deserialize( deserializer)?;
// 
//         deserialize_psf( s).map_err( de::Error::custom)
//     }
// }
// 
// pub fn serialize_psf<T>( &PSF( ref content,_) : &PSF<T>) -> String { // Vec<u8> {
//     base64::encode_config( &content, base64::URL_SAFE)
// }
// 
// pub fn deserialize_psf<T>( encoded : String) -> Result<PSF<T>, &'static str> {
//     match base64::decode_config( &encoded, base64::URL_SAFE) {
//         Ok(s) => Ok( PSF( s, PhantomData)),
//         Err(_) => Err("invalid Base64Url encoding")
//     }
// }

pub trait AlgorithmId {
    fn to_algorithm_id( &Self) -> &'static str;
    fn from_algorithm_id( &str) -> Option<Self> where Self : Sized;
}

pub trait ToIdentifier {
    fn to_identifier( &Self) -> PKAIdentifier;
}

pub trait EncodePSF {
    fn encode_psf( &Self) -> Vec<u8> where Self : Sized;
}

pub trait DecodePSF {
    type Algorithm;
    fn decode_psf( &Self::Algorithm, &Vec<u8>) -> Result<Self,&'static str> where Self : Sized;
}

pub fn generate_identifier( raw : Vec<u8>) -> PKAIdentifier {
    let mut hash = ripemd160( &sha256( &raw));
    let checksum = checksum_identifier( &hash);
    hash.extend( checksum);
    hash.to_base58()
}

fn checksum_identifier( ident : &Vec<u8>) -> Vec<u8> {
    let mut v = sha256( &sha256( ident));
    v.truncate( 4);
    v
}

fn sha256<'a>( d :&Vec<u8>) -> Vec<u8> {
    digest( &SHA256, &d).as_ref().to_vec()
}

fn ripemd160( d : &Vec<u8>) -> Vec<u8> {
    let mut h = Ripemd160::new();
    h.input( d);
    h.result().to_vec()
}
