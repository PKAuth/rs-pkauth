
use boolinator::Boolinator;
use crypto_abstract::{ToPublicKey};
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
                        k => {
                            Err(de::Error::unknown_field(k, FIELDS))?;
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
                        k => {
                            Err(de::Error::unknown_field(k, FIELDS))?;
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

impl EncodePSF for PrivateKey {
    fn encode_psf( _ : &PrivateKey) -> Vec<u8> {
        unimplemented!()
    }
}

impl DecodePSF for PrivateKey {
    type Algorithm = Algorithm;

    fn decode_psf( alg : &Algorithm, psf : &Vec<u8>) -> Result<PrivateKey, &'static str> where Self : Sized {
        unimplemented!()
    }
}

impl EncodePSF for PublicKey {
    fn encode_psf( _ : &PublicKey) -> Vec<u8> {
        unimplemented!()
    }
}

impl DecodePSF for PublicKey {
    type Algorithm = Algorithm;

    fn decode_psf( alg : &Algorithm, psf : &Vec<u8>) -> Result<PublicKey, &'static str> where Self : Sized {
        unimplemented!()
    }
}

impl EncodePSF for Signature {
    fn encode_psf( _ : &Signature) -> Vec<u8> {
        unimplemented!()
    }
}

impl DecodePSF for Signature {
    type Algorithm = Algorithm;

    fn decode_psf( alg : &Algorithm, psf : &Vec<u8>) -> Result<Signature, &'static str> where Self : Sized {
        unimplemented!()
    }
}

impl AlgorithmId for Algorithm {
    fn to_algorithm_id( alg : &Algorithm) -> &'static str {
        match *alg {
            Algorithm::AAEd25519 => "auth-ed25519"
        }
    }

    fn from_algorithm_id( alg : &str) -> Option<Self> {
        match alg {
            "auth-ed25519" => Some( Algorithm::AAEd25519),
            _ => None
        }
    }
}

