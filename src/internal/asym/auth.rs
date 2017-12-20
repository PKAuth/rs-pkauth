
use crypto_abstract::{ToPublicKey};
use crypto_abstract::asym::auth::{PublicKey, PrivateKey, Algorithm, Signature};

use {ToIdentifier, AlgorithmId};
use internal::{PKAIdentifier, generate_identifier, EncodePSF, DecodePSF};

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

