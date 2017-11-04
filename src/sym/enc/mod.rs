
use crypto_abstract::sym::enc::*;
pub use crypto_abstract::sym::enc::{gen, Key, Algorithm};
use serde::ser::{Serialize, Serializer, SerializeStruct};

use internal::PKAIdentifier;

pub struct PKASymEncrypted {
    ciphertext : CipherText,
    identifier : PKAIdentifier,
    algorithm : Algorithm
}

impl Serialize for PKASymEncrypted {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let mut s = serializer.serialize_struct("PKASymEncrypted", 3)?;
        s.serialize_field( "ciphertext", "TODO");
        s.serialize_field( "identifier", "TODO");
        s.serialize_field( "algorithm", "TODO");
        s.end()
    }
}

