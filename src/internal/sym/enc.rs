
use boolinator::Boolinator;
use crypto_abstract::sym::enc;
use crypto_abstract::sym::enc::{Key, Algorithm, CipherText};
use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde::de;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use std::fmt;
use std::marker::PhantomData;

use internal::{ToIdentifier, PKAIdentifier, AlgorithmId, PSF, EncodePSF, generate_identifier, DecodePSF, PKAJ, serialize_psf, deserialize_psf};

use ToAlgorithm;

impl<'a> Serialize for PKAJ<&'a Key> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S:Serializer {
        let mut o = serializer.serialize_struct("Key", 2)?;

        o.serialize_field( "key", &serialize_psf( self.pkaj))?;
        o.serialize_field( "algorithm", AlgorithmId::to_algorithm_id( &ToAlgorithm::to_algorithm( self.pkaj)))?;

        o.end()
    }
}

impl<'d> Deserialize<'d> for PKAJ<Key> {
    fn deserialize<D>( deserializer: D) -> Result<PKAJ<Key>, D::Error> where D : Deserializer<'d> {

        struct V;

        const FIELDS: &'static [&'static str] = &["key","algorithm"];

        impl<'d> Visitor<'d> for V {
            type Value = PKAJ<Key>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("JSON Key")
            }

            fn visit_map<U>(self, mut map: U) -> Result<PKAJ<Key>, U::Error> where U: MapAccess<'d> {
                let mut ident = None;
                let mut key = None;
                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "algorithm" => {
                            ident.is_none().ok_or( de::Error::duplicate_field("algorithm"))?;
                            ident = Some( map.next_value()?);
                        }
                        "key" => {
                            key.is_none().ok_or( de::Error::duplicate_field( "key"))?;
                            key = Some( map.next_value()?);
                        }
                        k => {
                            Err(de::Error::unknown_field(k, FIELDS))?;
                        }
                    }
                }

                let ident : String = ident.ok_or_else(|| de::Error::missing_field("algorithm"))?;
                let key = key.ok_or_else(|| de::Error::missing_field("key"))?;

                let alg = AlgorithmId::from_algorithm_id( &ident).ok_or( de::Error::custom( "invalid algorithm identifier"))?;
                let key = deserialize_psf( &alg, &key).map_err(de::Error::custom)?;

                Ok( PKAJ{ pkaj: key})
            }
        }

        deserializer.deserialize_struct( "Key", FIELDS, V)
    }
}

impl ToIdentifier for Key {
    fn to_identifier( key : &Key) -> PKAIdentifier {
        let serialized = EncodePSF::encode_psf( key);
        generate_identifier( serialized)
    }
}

impl EncodePSF for Key {
    fn encode_psf( key : &Key) -> PSF<Key> {
        match *key {
            Key::SEAesGcm256( key) =>
                // TODO: Test this XXX
                PSF( key.to_vec(), PhantomData)
        }
    }
}

impl DecodePSF for Key {
    type Algorithm = enc::Algorithm;

    fn decode_psf( alg : &Algorithm, &PSF( ref psf, _) : &PSF<Key>) -> Result<Key, &'static str> where Self : Sized {
        match alg {
            &Algorithm::SEAesGcm256 => {
                (psf.len() == 32).ok_or("Key is wrong length.")?;

                let mut key = [0u8;32];

                for (place, element) in key.iter_mut().zip( psf.into_iter()) {
                    *place = *element;
                }

                // TODO: test this XXX
                Ok( Key::SEAesGcm256( key))
            }
        }
    }
}

impl AlgorithmId for Algorithm {
    fn to_algorithm_id( alg : &Algorithm) -> &'static str {
        match *alg {
            Algorithm::SEAesGcm256 => "enc-aesgcm256"
        }
    }

    fn from_algorithm_id( alg : &str) -> Option<Self> {
        match alg {
            "enc-aesgcm256" => Some( Algorithm::SEAesGcm256),
            _ => None
        }
    }
}

// Can't have orphans.
// impl Serialize for Algorithm {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S:Serializer {
//         self.to_algorithm_id().serialize( serializer)
//     }
// }

// impl Deserialize for Algorithm {
// 
// }

pub fn serialize_algorithm<S>(alg : &Algorithm, serializer: S) -> Result<S::Ok, S::Error> where S : Serializer {
    AlgorithmId::to_algorithm_id( alg).serialize( serializer)
}

// pub fn deserialize_algorithm<'d, D>( deserializer: D) -> Result<Algorithm, D::Error> where D : Deserializer<'d> {
//     let s = <&str>::deserialize(deserializer)?;
//     AlgorithmId::from_algorithm_id( s).ok_or( de::Error::custom( "Invalid algorithm identifier."))
// }

impl EncodePSF for CipherText {
    fn encode_psf( cipher : &CipherText) -> PSF<CipherText> {
        match cipher {
            &CipherText::SEAesGcm256( ref nonce, ref ciphertext) => {
                // TODO: Test this. Correct order? XXX
                let mut v = Vec::with_capacity( nonce.len() + ciphertext.len());
                v.extend( nonce.iter());
                v.extend( ciphertext.iter());
                PSF( v, PhantomData)
            }
        }
    }
}

impl DecodePSF for CipherText {
    type Algorithm = enc::Algorithm;

    fn decode_psf( alg : &Algorithm, &PSF( ref psf, _) : &PSF<CipherText>) -> Result<CipherText, &'static str> where Self : Sized {
        match alg {
            &Algorithm::SEAesGcm256 => {
                let l = 12;
                (psf.len() > l).ok_or("Invalid PSF encoded ciphertext.")?;

                let (nonce, cipher) = psf.split_at( l);

                Ok( CipherText::SEAesGcm256( nonce.to_vec(), cipher.to_vec()))
            }
        }
    }
}

