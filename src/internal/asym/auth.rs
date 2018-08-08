
// Helpful reference for existing key encodings: https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/

use boolinator::Boolinator;
use crypto_abstract::{ToPublicKey};
// use crypto_abstract::internal::asym::auth::ed25519;
use crypto_abstract::asym::auth::{PublicKey, PrivateKey, Algorithm, Signature};
use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde::de;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use std::fmt;

use {ToIdentifier, AlgorithmId, ToAlgorithm};
use internal::{PKAIdentifier, generate_identifier, EncodePSF, DecodePSF, PKAJ, serialize_psf, deserialize_psf};

impl<'a> Serialize for PKAJ<&'a PublicKey> {
    fn serialize<S>( &self, serializer : S) -> Result<S::Ok, S::Error> where S : Serializer {
        let mut o = serializer.serialize_struct( "PublicKey", 2)?;
        
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
                formatter.write_str("JSON PublicKey")
            }

            fn visit_map<U>(self, mut map : U) -> Result<PKAJ<PublicKey>, U::Error> where U : MapAccess<'d> {
                let mut public_key = None;
                let mut algorithm = None;
                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "algorithm" => {
                            algorithm.is_none().ok_or( de::Error::duplicate_field( "algorithm"))?;
                            algorithm = Some( map.next_value()?);
                        }
                        "public_key" => {
                            public_key.is_none().ok_or( de::Error::duplicate_field( "public_key"))?;
                            public_key = Some( map.next_value()?);
                        }
                        _k => {
                            // Skip unknown fields.
                            let _ : Result<(),U::Error> = map.next_value();
                            // Err(de::Error::unknown_field(k, FIELDS))?;
                        }
                    }
                }

                let algorithm : String = algorithm.ok_or_else(|| de::Error::missing_field( "algorithm"))?;
                let public_key = public_key.ok_or_else(|| de::Error::missing_field( "public_key"))?;

                let algorithm = AlgorithmId::from_algorithm_id( &algorithm).ok_or( de::Error::custom( "invalid algorithm identifier"))?;
                let public_key = deserialize_psf( &algorithm, &public_key).map_err( de::Error::custom)?;

                Ok( PKAJ{ pkaj : public_key})
            }
        }

        deserializer.deserialize_struct( "PublicKey", FIELDS, V)
    }
}

impl<'a> Serialize for PKAJ<&'a PrivateKey> {
    fn serialize<S>( &self, serializer : S) -> Result<S::Ok, S::Error> where S : Serializer {
        let mut o = serializer.serialize_struct( "PrivateKey", 2)?;

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
                formatter.write_str("JSON PrivateKey")
            }

            fn visit_map<U>(self, mut map: U) -> Result<PKAJ<PrivateKey>, U::Error> where U: MapAccess<'d> {
                let mut algorithm = None;
                let mut private_key = None;
                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "private_key" => {
                            private_key.is_none().ok_or( de::Error::duplicate_field( "private_key"))?;
                            private_key = Some( map.next_value()?);
                        }
                        "algorithm" => {
                            algorithm.is_none().ok_or( de::Error::duplicate_field( "algorithm"))?;
                            algorithm = Some( map.next_value()?);
                        }
                        _k => {
                            // Skip unknown fields.
                            let _ : Result<(),U::Error> = map.next_value();
                            // Err(de::Error::unknown_field(k, FIELDS))?;
                        }
                    }
                }

                let algorithm : String = algorithm.ok_or_else(|| de::Error::missing_field( "algorithm"))?;
                let private_key = private_key.ok_or_else(|| de::Error::missing_field( "private_key"))?;

                let algorithm = AlgorithmId::from_algorithm_id( &algorithm).ok_or( de::Error::custom( "invalid algorithm identifier"))?;
                let private_key = deserialize_psf( &algorithm, &private_key).map_err( de::Error::custom)?;

                Ok( PKAJ{ pkaj: private_key})
            }
        }

        deserializer.deserialize_struct( "PrivateKey", FIELDS, V)
    }
}

impl ToIdentifier for PublicKey {
    fn to_identifier( key : &PublicKey) -> PKAIdentifier {
        let serialized = EncodePSF::encode_psf( key);

        generate_identifier( serialized)
    }
}

impl ToIdentifier for PrivateKey {
    fn to_identifier( key : &PrivateKey) -> PKAIdentifier {
        ToIdentifier::to_identifier( &ToPublicKey::to_public_key( key))
    }
}

const PRIVATEKEYPOSITION : usize = 16;
const PRIVATEKEYLENGTH : usize = 32;
const PUBLICKEYPOSITION : usize = 53;
const PUBLICKEYLENGTH : usize = 32;

impl EncodePSF for PrivateKey {
    fn encode_psf( private_key : &PrivateKey) -> Vec<u8> {
        match *private_key {
            PrivateKey::AAEd25519( private_key) => {
                // Big endian?
                //
                // k - 32 bytes
                // A - 32 bytes
                // TODO: Verify this

                let mut key = [0; PRIVATEKEYLENGTH + PUBLICKEYLENGTH];

                // Copy over k components.
                {
                    let k = &private_key[PRIVATEKEYPOSITION .. PRIVATEKEYPOSITION+PRIVATEKEYLENGTH];
                    let k_new = &mut key[0 .. PRIVATEKEYLENGTH];
                    for (place, element) in k_new.iter_mut().zip( k.into_iter()) {
                        *place = *element;
                    }
                }

                // Copy over A components.
                {
                    let a = &private_key[PUBLICKEYPOSITION .. PUBLICKEYPOSITION+PUBLICKEYLENGTH];
                    let a_new = &mut key[ PRIVATEKEYLENGTH .. PRIVATEKEYLENGTH+PUBLICKEYLENGTH];
                    for (place, element) in a_new.iter_mut().zip( a.into_iter()) {
                        *place = *element;
                    }
                }

                // TODO: test this XXX
                key.to_vec()
            }
        }
    }
}

impl DecodePSF for PrivateKey {
    type Algorithm = Algorithm;

    fn decode_psf( alg : &Algorithm, psf : &Vec<u8>) -> Result<PrivateKey, &'static str> where Self : Sized {
        match *alg {
            Algorithm::AAEd25519 => {
                (psf.len() == PUBLICKEYLENGTH + PRIVATEKEYLENGTH).ok_or("Private key is wrong length.")?;

                // Prefill key with pkcs8 constants (used by ring).
                let mut key : [u8; 85] = [ 
                      0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
                    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                    , 0xa1, 0x23, 0x03, 0x21, 0x00
                    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                    ];

                // Copy over k.
                {
                    let k = &psf[0 .. PRIVATEKEYLENGTH];
                    let k_new = &mut key[PRIVATEKEYPOSITION .. PRIVATEKEYPOSITION+PRIVATEKEYLENGTH];
                    for (place, element) in k_new.iter_mut().zip( k) {
                        *place = *element;
                    }
                }

                // Copy over A.
                {
                    let a = &psf[PRIVATEKEYLENGTH .. PRIVATEKEYLENGTH+PUBLICKEYLENGTH];
                    let a_new = &mut key[PUBLICKEYPOSITION .. PUBLICKEYPOSITION+PUBLICKEYLENGTH];
                    for (place, element) in a_new.iter_mut().zip( a) {
                        *place = *element;
                    }
                }
                
                Ok( PrivateKey::AAEd25519( key))
            }
        }
    }
}

// JP: Should we get these constants from crypto-abstract? I don't want to expose them there though.

impl EncodePSF for PublicKey {
    fn encode_psf( public_key : &PublicKey) -> Vec<u8> {
        match *public_key {
            PublicKey::AAEd25519( public_key) => {
                // Big endian?
                //
                // A - 32 bytes
                // TODO: Verify this

                public_key.as_ref().to_vec()
            }
        }
    }
}

impl DecodePSF for PublicKey {
    type Algorithm = Algorithm;

    fn decode_psf( alg : &Algorithm, psf : &Vec<u8>) -> Result<PublicKey, &'static str> where Self : Sized {
        match *alg {
            Algorithm::AAEd25519 => {
                (psf.len() == PUBLICKEYLENGTH).ok_or( "Public key is wrong length")?;

                let mut public_key = [0u8; PUBLICKEYLENGTH];
                for (place, element) in public_key.iter_mut().zip( psf.into_iter()) {
                    *place = *element;
                }

                Ok( PublicKey::AAEd25519( public_key))
            }
        }
    }
}

const SIGNATURELENGTH : usize = 64;

impl EncodePSF for Signature {
    fn encode_psf( signature : &Signature) -> Vec<u8> {
        match *signature {
            Signature::AAEd25519( signature) => {
                // Big endian?
                //
                // R - 32 bytes
                // S - 32 bytes
                // TODO: Verify this

                signature.as_ref().to_vec()
            }
        }

    }
}

impl DecodePSF for Signature {
    type Algorithm = Algorithm;

    fn decode_psf( alg : &Algorithm, psf : &Vec<u8>) -> Result<Signature, &'static str> where Self : Sized {
        match alg {
            &Algorithm::AAEd25519 => {
                (psf.len() == SIGNATURELENGTH).ok_or( "Signature is wrong length")?;

                let mut signature = [0u8; SIGNATURELENGTH];
                for (place, element) in signature.iter_mut().zip( psf.into_iter()) {
                    *place = *element;
                }

                // TODO: test this XXX
                Ok( Signature::AAEd25519( signature))
            }
        }
    }
}

impl AlgorithmId for Algorithm {
    fn to_algorithm_id( alg : &Algorithm) -> &'static str {
        match *alg {
            Algorithm::AAEd25519 => "aa-ed25519"
        }
    }

    fn from_algorithm_id( alg : &str) -> Option<Self> {
        match alg {
            "aa-ed25519" => Some( Algorithm::AAEd25519),
            _ => None
        }
    }
}

