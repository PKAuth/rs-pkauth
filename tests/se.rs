extern crate pkauth;
extern crate serde_json;

use pkauth::sym::enc as se;
use pkauth::{PKAJ};

#[test]
fn se_manual_tests() {
    se_manual_test( "{\"key\":\"1quLbjzIufNwHh7Oc5ayXiosE3RoJBEDGH_cEcoQfDE=\",\"algorithm\":\"enc-aesgcm256\"}", 
                    "{\"ciphertext\":\"edzNkvuqE-BUGS2Y0RXnt9C4d52B7v8boQtdn1nkdSWesa_Y9RRW2c1acAAIv8YHeb0=\",\"identifier\":\"GzD1i8BgqvT7tTd24K9CrHqWRqMSbfVsp\",\"algorithm\":\"enc-aesgcm256\"}",
                    "this is rust plaintext");

    se_manual_test( "{\"key\":\"blZ9VO3AZxbHbv7RflznaEvWC7j3X1FH6pOTwpcYqo4=\",\"algorithm\":\"enc-aesgcm256\"}",
                    "{\"ciphertext\":\"AAAAAAAAAAAAAAAAtdJTGLXxsArHcNkIA3LwAMaKEzTcMXDwmKnh5izO04EMsMTg0Ho=\",\"identifier\":\"C3drTBjjW16c1gzFsoqTBihvKiVq2MBqG\",\"algorithm\":\"enc-aesgcm256\"}",
                    "this is some plaintext");

    se_manual_test( "{\"key\":\"bd6QR9EkrVX9Aq-eCfukKgt_uv6kj5OdFodx6MSwaZ4=\",\"algorithm\":\"enc-aesgcm256\"}",
                    "{\"identifier\":\"5bUT5uwxft5fGagNjWJtXphwrPmUoWQRW\",\"algorithm\":\"enc-aesgcm256\",\"ciphertext\":\"EuoKbWVgDB-KZhc6BYNxzXvJPAMQps_ra9mmtMQAvdo66Ur8fWppIgIOwOcouCdUNoY=\"}", 
                    "this is some plaintext");


    se_manual_test( "{\"key\":\"PZ_f3UfYRiAqM99sd4hRwEMVdzYoxjLrPR65grAeSSY=\",\"algorithm\":\"enc-aesgcm256\"}",
                    "{\"identifier\":\"B1qP31EQfcjhhVisNNyuJTnpRXBw8HkNg\",\"algorithm\":\"enc-aesgcm256\",\"ciphertext\":\"AAAAAAAAAAAAAAAALxZa756HxuCOh0hXH8AF-5VBH3MDohg3YOkP6s91R6PT1HCJ2BA=\"}",
                    "this is some plaintext");
}

fn se_manual_test( key_s : &str, cipher_s : &str, plain_s : &str) {
    // print!("********************\n{}\n", cipher_s);
    let key_b = key_s.to_owned().into_bytes();
    let cipher = cipher_s.to_owned().into_bytes();
    let plain = plain_s.to_owned().into_bytes();
    // print!("********************\n{:?}\n", plain);
    let key_m : PKAJ<se::Key> = serde_json::from_slice( &key_b).unwrap();
    let key : se::Key = key_m.pkaj;
    let dec = se::decrypt_content_bs( &key, &cipher).unwrap();
    assert_eq!( plain, dec);
}
