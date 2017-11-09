
pub mod sym;

use base64;
use std::marker::PhantomData;

pub type PKAIdentifier = String;

pub struct PSF<T> ( Vec<u8>, PhantomData<T>); // JP: PhantomData is annoying. Hopefully we can eventually drop.

fn serialize_psf<T>( PSF( content,_) : PSF<T>) -> String { // Vec<u8> {
    base64::encode_config( &content, base64::URL_SAFE)
}

fn deserialize_ps<T>( encoded : String) -> Result<PSF<T>, &'static str> {
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

trait DecodePSF {
    fn decode_psf( &PSF<Self>) -> Result<Self,String> where Self : Sized;
}
