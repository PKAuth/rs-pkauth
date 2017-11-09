
extern crate base64;
extern crate crypto_abstract;
extern crate ring;
extern crate ripemd160;
extern crate rust_base58;
extern crate serde;

mod internal;
pub mod sym;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
