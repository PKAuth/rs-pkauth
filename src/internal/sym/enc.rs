
use crypto_abstract::sym::enc::{Key, Algorithm, CipherText};

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
                unimplemented!()
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

impl EncodePSF for CipherText {
    fn encode_psf( ref cipher : &CipherText) -> PSF<CipherText> {
        unimplemented!()
    }
}
