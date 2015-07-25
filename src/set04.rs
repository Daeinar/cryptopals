
use set02::{pkcs7_pad,pkcs7_unpad,aes128_cbc_encrypt,aes128_cbc_decrypt};
use utils::{random_bytes};

pub struct CBCOracleKeyIV { key: Vec<u8> }

impl CBCOracleKeyIV {
pub fn new() -> CBCOracleKeyIV {
    CBCOracleKeyIV { key: random_bytes(16) }
    }
    pub fn encrypt(&self, m: &[u8]) -> Vec<u8> {
        aes128_cbc_encrypt(&self.key, &self.key, &pkcs7_pad(&m,16))
    }
    pub fn decrypt(&self, c: &[u8] ) -> Option<Vec<u8>> {
        pkcs7_unpad(&aes128_cbc_decrypt(&self.key, &self.key, &c),16)
    }
}

pub fn is_ascii(x: &[u8]) -> bool {
    for i in 0..x.len() {
        if 0x7F < x[i] {
            return false;
        }
    }
    true
}
