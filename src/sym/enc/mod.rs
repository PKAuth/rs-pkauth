// #![feature(plugin)]
// #![plugin(serde_macros)]

use crypto_abstract::sym::enc::*;
pub use crypto_abstract::sym::enc::{gen, Key, Algorithm};
use std::fmt;
use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde::de::{Visitor, MapAccess, Deserialize, Deserializer};

use internal::{PKAIdentifier,PSF};

pub struct PKASymEncrypted {
    ciphertext : PSF<CipherText>,
    identifier : PKAIdentifier,
    algorithm : Algorithm
}

// impl Serialize for PKASymEncrypted {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
//         let mut s = serializer.serialize_struct("PKASymEncrypted", 3)?;
//         s.serialize_field( "ciphertext", "TODO");
//         s.serialize_field( "identifier", "TODO");
//         s.serialize_field( "algorithm", "TODO");
//         s.end()
//     }
// }
// 
// impl<'d> Deserialize<'d> for PKASymEncrypted {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'d> {
// 
//         #[derive(Deserialize)]
//         #[serde(field_identifier, rename_all = "lowercase")]
//         enum Field {Ciphertext, Identifier, Algorithm};
// 
//         struct PKASEVisitor;
// 
//         impl Visitor<'d> for PKASEVisitor {
//             type Value = PKASymEncrypted;
// 
//             fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                 formatter.write_str( "PKAuth encoded symmetrically encrypted content");
//             }
// 
//             fn visit_map<V>(self, mut map: V) -> Result<PKASymEncrypted, V::Error> where V: MapAccess<'d> {
//                 let mut ciphertext = None;
//                 let mut identifier = None;
//                 let mut algorithm = None;
// 
//                 while let Some(key) = map.next_key()? {
//                     unimplemented!();
//                 }
// 
//                 unimplemented!();
//             }
//         }
// 
//         const FIELDS: &'static [&'static str] = &["ciphertext","identifier","algorithm"];
//         deserializer.deserialize_struct("PKASymEncrypted", FIELDS, PKASEVisitor)
//     }
// 
// }
