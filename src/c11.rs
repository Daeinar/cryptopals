extern crate rand;

use self::rand::{thread_rng, Rng};
use c07::aes128_ecb_encrypt;
use c08::is_ecb_ciphertext;
use c09::pkcs7;
use c10::aes128_cbc_encrypt;

pub fn encryption_oracle(x: &[u8]) -> Vec<u8> {

    let mut rng = thread_rng();

    // random 16-byte key
    let mut k = vec![0u8; 16];
    rng.fill_bytes(&mut k);

    // add random padding before and after message
    let mut m = vec![0u8; rng.gen_range(5,11)];
    rng.fill_bytes(&mut m);
    let mut n = vec![0u8; rng.gen_range(5,11)];
    rng.fill_bytes(&mut n);
    m.extend(x.to_vec());
    m.extend(n);

    // pad message to AES block size
    m = pkcs7(&m,16);

    match rand::random() {
        true => {
            print!("ECB: ");
            aes128_ecb_encrypt(&k, &m)
            },
        false => {
            print!("CBC: ");
            let mut iv = [0u8; 16];
            rng.fill_bytes(&mut iv);
            aes128_cbc_encrypt(&k, &iv, &m)
        },
    }
}


// due to the added random padding in the oracle the detection mechanism needs
// at least two repeating 32-byte sequences (can this be improved?)
pub fn is_ecb_oracle<Oracle>(x: &[u8], o: Oracle) -> bool
    where Oracle: Fn(&[u8]) -> Vec<u8> {
    is_ecb_ciphertext(&o(x),16)
}
