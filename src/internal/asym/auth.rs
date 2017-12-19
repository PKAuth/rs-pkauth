
use crypto_abstract::{ToPublicKey};
use crypto_abstract::asym::auth::{PublicKey, PrivateKey};

use {ToIdentifier};
use internal::{PKAIdentifier, generate_identifier, EncodePSF};

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

impl EncodePSF for PublicKey {
    fn encode_psf( _ : &PublicKey) -> Vec<u8> {
        unimplemented!()
    }
}
