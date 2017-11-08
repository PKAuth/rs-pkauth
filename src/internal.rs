
use base64;

pub type PKAIdentifier = String;

pub struct PSF {
      content : Vec<u8>
    }

fn serialize_psf( PSF{ content} : PSF) -> String { // Vec<u8> {
    base64::encode_config( &content, base64::URL_SAFE)
}

fn deserialize_psf( encoded : String) -> Result<PSF, &'static str> {
    match base64::decode_config( &encoded, base64::URL_SAFE) {
        Ok(s) => Ok( PSF{ content:s}),
        Err(_) => Err("invalid Base64Url encoding")
    }
}

