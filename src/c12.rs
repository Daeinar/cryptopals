extern crate rand;

use self::rand::{thread_rng, Rng};
use c07::aes128_ecb_encrypt;
use c09::pkcs7;

pub struct ECBOracle { key: Vec<u8>, msg: Vec<u8> } // msg is an "unknown" string and appended at each query before encryption

impl ECBOracle {
    pub fn new(m : &[u8]) -> ECBOracle {
        let mut rng = thread_rng();
        let mut k = vec![0u8; 16];
        rng.fill_bytes(&mut k);
        ECBOracle { key: k, msg: m.to_vec() }
    }
    pub fn encrypt(&self, m: &[u8]) -> Vec<u8> {
        let mut n = m.to_vec();
        n.extend(self.msg.clone());
        aes128_ecb_encrypt(&self.key,&pkcs7(&n,16))
    }
    pub fn print_key(&self) {
        for i in 0..self.key.len() {
            print!("{:02X} ", self.key[i]);
        }
        println!("");
    }
}
