
use crypto_abstract::sym::enc::{Key, Algorithm, CipherText};
use serde::ser::{Serialize, Serializer};
use std::marker::PhantomData;

use internal::{ToIdentifier, PKAIdentifier, AlgorithmId, PSF, EncodePSF, generate_identifier};

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

