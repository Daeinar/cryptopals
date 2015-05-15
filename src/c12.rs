extern crate rand;

use self::rand::{thread_rng, Rng};
use c07::{aes128_ecb_encrypt};
use c10::{aes128_cbc_encrypt};

pub struct ECBOracle { key: Vec<u8>, }
pub struct CBCOracle { key: Vec<u8>, }

impl ECBOracle {
    pub fn new() -> ECBOracle {
        let mut rng = thread_rng();
        let mut k = vec![0u8; 16];
        rng.fill_bytes(&mut k);
        ECBOracle { key: k }
    }
    pub fn encrypt(&self, m: &[u8]) -> Vec<u8> {
        aes128_ecb_encrypt(&self.key,&m)
    }
    pub fn print_key(&self) {
        for i in 0..self.key.len() {
            print!("{:02X} ", self.key[i]);
        }
        println!("");
    }
}


impl CBCOracle {
    pub fn new() -> CBCOracle {
        let mut rng = thread_rng();
        let mut k = vec![0u8; 16];
        rng.fill_bytes(&mut k);
        CBCOracle { key: k }
    }
    pub fn encrypt(&self, iv: &[u8], m: &[u8]) -> Vec<u8> {
        aes128_cbc_encrypt(&self.key,&iv,&m)
    }
    pub fn print_key(&self) {
        for i in 0..self.key.len() {
            print!("{:02X} ", self.key[i]);
        }
        println!("");
    }
}
