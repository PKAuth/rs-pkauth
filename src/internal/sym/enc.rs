
use boolinator::Boolinator;
use crypto_abstract::sym::enc;
use crypto_abstract::sym::enc::{Key, Algorithm, CipherText};
use ring::aead;
use serde::ser::{Serialize, Serializer};
use serde::de;
use serde::de::{Deserialize, Deserializer};
use std::marker::PhantomData;

use internal::{ToIdentifier, PKAIdentifier, AlgorithmId, PSF, EncodePSF, generate_identifier, DecodePSF};

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
                (psf.len() == 256).ok_or("Key is wrong length.");

                let mut key = [0u8;256];

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

pub fn deserialize_algorithm<'d, D>( deserializer: D) -> Result<Algorithm, D::Error> where D : Deserializer<'d> {
    let s = <&str>::deserialize(deserializer)?;
    AlgorithmId::from_algorithm_id( s).ok_or( de::Error::custom( "Invalid algorithm identifier."))
}

impl EncodePSF for CipherText {
    fn encode_psf( cipher : &CipherText) -> PSF<CipherText> {
        match cipher {
            &CipherText::SEAesGcm256( ref nonce, ref ciphertext) => {
                // TODO: Test this. Correct order? XXX
                let v = Vec::with_capacity( nonce.len() + ciphertext.len());
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
                let l = aead::AES_256_GCM.tag_len();
                (psf.len() > l).ok_or("Invalid PSF encoded ciphertext.")?;

                let (nonce, cipher) = psf.split_at( l);

                Ok( CipherText::SEAesGcm256( nonce.to_vec(), cipher.to_vec()))
            }
        }
    }
}

