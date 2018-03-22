
use boolinator::Boolinator;
use crypto_abstract::asym::enc;
use crypto_abstract::asym::enc::{PublicKey, Algorithm, PrivateKey}; // , CipherText};
use ring::agreement::{ReusablePrivateKey, X25519};
use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde::de;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use std::fmt;
use untrusted::Input;

use internal::{AlgorithmId, EncodePSF, DecodePSF, PKAJ, serialize_psf, deserialize_psf, u8_to_fixed_length_32}; // ToIdentifier, PKAIdentifier, 
use ToAlgorithm;

impl<'a> Serialize for PKAJ<&'a PublicKey> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S:Serializer {
        let mut o = serializer.serialize_struct("PublicKey", 2)?;

        o.serialize_field( "public_key", &serialize_psf( self.pkaj))?;
        o.serialize_field( "algorithm", AlgorithmId::to_algorithm_id( &ToAlgorithm::to_algorithm( self.pkaj)))?;

        o.end()
    }
}

impl<'d> Deserialize<'d> for PKAJ<PublicKey> {
    fn deserialize<D>( deserializer: D) -> Result<PKAJ<PublicKey>, D::Error> where D : Deserializer<'d> {
        struct V;

        const FIELDS: &'static [&'static str] = &["public_key","algorithm"];

        impl<'d> Visitor<'d> for V {
            type Value = PKAJ<PublicKey>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("JSON Key")
            }

            fn visit_map<U>(self, mut map: U) -> Result<PKAJ<PublicKey>, U::Error> where U: MapAccess<'d> {
                let mut ident = None;
                let mut key = None;
                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "algorithm" => {
                            ident.is_none().ok_or( de::Error::duplicate_field("algorithm"))?;
                            ident = Some( map.next_value()?);
                        }
                        "public_key" => {
                            key.is_none().ok_or( de::Error::duplicate_field( "key"))?;
                            key = Some( map.next_value()?);
                        }
                        k => {
                            Err(de::Error::unknown_field(k, FIELDS))?;
                        }
                    }
                }

                let ident : String = ident.ok_or_else(|| de::Error::missing_field("algorithm"))?;
                let key = key.ok_or_else(|| de::Error::missing_field("public_key"))?;

                let alg = AlgorithmId::from_algorithm_id( &ident).ok_or( de::Error::custom( "invalid algorithm identifier"))?;
                let key = deserialize_psf( &alg, &key).map_err(de::Error::custom)?;

                Ok( PKAJ{ pkaj: key})
            }
        }

        deserializer.deserialize_struct( "PublicKey", FIELDS, V)
    }
}

impl EncodePSF for PublicKey {
    fn encode_psf( key : &PublicKey) -> Vec<u8> {
        match *key {
            PublicKey::AEX25519( key) => {
                // TODO: Test this XXX
                key.to_vec()
            }
        }
    }
}

impl DecodePSF for PublicKey {
    type Algorithm = enc::Algorithm;

    fn decode_psf( alg : &Algorithm, psf : &Vec<u8>) -> Result<PublicKey, &'static str> where Self : Sized {
        match alg {
            &Algorithm::AEX25519 => {
                let key = u8_to_fixed_length_32( psf).ok_or("Public key is wrong length.")?;
                
                // TODO: test this XXX
                Ok( PublicKey::AEX25519( key))
            }
        }
    }
}
impl AlgorithmId for Algorithm {
    fn to_algorithm_id( alg : &Algorithm) -> &'static str {
        match *alg {
            // TODO: RSA XXX
            Algorithm::AEX25519 => "enc-x25519"
        }
    }

    fn from_algorithm_id( alg : &str) -> Option<Self> {
        match alg {
            "enc-x25519" => Some( Algorithm::AEX25519),
            _ => None
        }
    }
}

impl<'a> Serialize for PKAJ<&'a PrivateKey> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S:Serializer {
        let mut o = serializer.serialize_struct("PrivateKey", 2)?;

        o.serialize_field( "private_key", &serialize_psf( self.pkaj))?;
        o.serialize_field( "algorithm", AlgorithmId::to_algorithm_id( &ToAlgorithm::to_algorithm( self.pkaj)))?;

        o.end()
    }
}

impl<'d> Deserialize<'d> for PKAJ<PrivateKey> {
    fn deserialize<D>( deserializer: D) -> Result<PKAJ<PrivateKey>, D::Error> where D : Deserializer<'d> {
        struct V;

        const FIELDS: &'static [&'static str] = &["private_key","algorithm"];

        impl<'d> Visitor<'d> for V {
            type Value = PKAJ<PrivateKey>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("JSON Key")
            }

            fn visit_map<U>(self, mut map: U) -> Result<PKAJ<PrivateKey>, U::Error> where U: MapAccess<'d> {
                let mut ident = None;
                let mut key = None;
                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "algorithm" => {
                            ident.is_none().ok_or( de::Error::duplicate_field("algorithm"))?;
                            ident = Some( map.next_value()?);
                        }
                        "private_key" => {
                            key.is_none().ok_or( de::Error::duplicate_field( "key"))?;
                            key = Some( map.next_value()?);
                        }
                        k => {
                            Err(de::Error::unknown_field(k, FIELDS))?;
                        }
                    }
                }

                let ident : String = ident.ok_or_else(|| de::Error::missing_field("algorithm"))?;
                let key = key.ok_or_else(|| de::Error::missing_field("private_key"))?;

                let alg = AlgorithmId::from_algorithm_id( &ident).ok_or( de::Error::custom( "invalid algorithm identifier"))?;
                let key = deserialize_psf( &alg, &key).map_err(de::Error::custom)?;

                Ok( PKAJ{ pkaj: key})
            }
        }

        deserializer.deserialize_struct( "PrivateKey", FIELDS, V)
    }
}

impl EncodePSF for PrivateKey {
    fn encode_psf( key : &PrivateKey) -> Vec<u8> {
        match *key {
            PrivateKey::AEX25519( ref key) => {
                // TODO: Test this. Verify length. XXX
                key.private_key_bytes().to_vec()
            }
        }
    }
}

impl DecodePSF for PrivateKey {
    type Algorithm = enc::Algorithm;

    fn decode_psf( alg : &Algorithm, psf : &Vec<u8>) -> Result<PrivateKey, &'static str> where Self : Sized {
        match alg {
            &Algorithm::AEX25519 => {
                // JP: Validate length and copy?
                // let key = u8_to_fixed_length_32( psf).ok_or("Private key is wrong length.")?;
                    
                let key = ReusablePrivateKey::from_bytes( &X25519, Input::from( &psf)).or( Err("Invalid private key."))?;

                // TODO: test this XXX
                Ok( PrivateKey::AEX25519( key))
            }
        }
    }
}
