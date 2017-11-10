
pub mod sym;

use base64;
use ring::digest::{digest, SHA256};
use ripemd160::{Ripemd160, Digest};
use rust_base58::base58::{ToBase58};
use serde::ser::{Serialize, Serializer};
use serde::de;
use serde::de::{Deserialize, Deserializer};
use std::marker::PhantomData;

pub type PKAIdentifier = String;

pub struct PSF<T> ( Vec<u8>, PhantomData<T>); // JP: PhantomData is annoying. Hopefully we can eventually drop.

impl<T> Serialize for PSF<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S:Serializer {
        serialize_psf( self).serialize( serializer)
    }
}

impl<'d, T> Deserialize<'d> for PSF<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D:Deserializer<'d> {
        let s = Deserialize::deserialize( deserializer)?;

        deserialize_psf( s).map_err( de::Error::custom)
    }
}

fn serialize_psf<T>( &PSF( ref content,_) : &PSF<T>) -> String { // Vec<u8> {
    base64::encode_config( &content, base64::URL_SAFE)
}

fn deserialize_psf<T>( encoded : String) -> Result<PSF<T>, &'static str> {
    match base64::decode_config( &encoded, base64::URL_SAFE) {
        Ok(s) => Ok( PSF( s, PhantomData)),
        Err(_) => Err("invalid Base64Url encoding")
    }
}

pub trait AlgorithmId {
    fn to_algorithm_id( &Self) -> &'static str;
    fn from_algorithm_id( &str) -> Option<Self> where Self : Sized;
}

pub trait ToIdentifier {
    fn to_identifier( &Self) -> PKAIdentifier;
}

pub trait EncodePSF {
    fn encode_psf( &Self) -> PSF<Self> where Self : Sized;
}

pub trait DecodePSF {
    fn decode_psf( &PSF<Self>) -> Result<Self,&'static str> where Self : Sized;
}

pub fn generate_identifier<T>( PSF(raw, _) : PSF<T>) -> PKAIdentifier {
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
