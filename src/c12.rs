extern crate rand;

use self::rand::{thread_rng, Rng};
use c07::{aes128_ecb_encrypt,aes128_ecb_decrypt};
use c09::pkcs7;

pub struct ECBOracle { key: Vec<u8>, prefix: Vec<u8>, suffix: Vec<u8>, mode: usize } // msg is an "unknown" string and appended at each query before encryption

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut x = vec![0u8; n];
    rng.fill_bytes(&mut x);
    x
}

impl ECBOracle {
    pub fn new() -> ECBOracle {
        ECBOracle { key: random_bytes(16), prefix: random_bytes(random_bytes(1)[0] as usize), suffix: vec![], mode: 0 }
    }
    pub fn encrypt(&self, m: &[u8]) -> Vec<u8> {
        let n = match self.mode {
            0 => m.to_vec(), // only encrypt msg
            1 => vec![m.to_vec(), self.suffix.clone()].concat(), // encrypt msg+suffix
            2 => vec![self.prefix.clone(), m.to_vec(), self.suffix.clone()].concat(), // encrypt prefix+msg+suffix
            _ => panic!("unknwon mode"),
        };
        //println!("prefix-length: {}", self.prefix.len());
        aes128_ecb_encrypt(&self.key,&pkcs7(&n,16))
    }
    pub fn decrypt(&self, c: &[u8]) -> Vec<u8> {
        aes128_ecb_decrypt(&self.key,&c)
    }
    pub fn set_mode(&mut self, mode: usize) {
        assert!(mode <= 2);
        self.mode = mode
    }
    pub fn set_suffix(&mut self, m: &[u8]) {
        self.suffix = m.to_vec();
    }
}


#[cfg(test)]
mod test {
    use c01::{decode_base64,hex};
    use c12::*;

    #[test]
    fn test_c12() {
        let pt = decode_base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        let mut oracle = ECBOracle::new(); // init ECB oracle
        oracle.set_suffix(&pt); // set "unknown" plaintext suffix
        oracle.set_mode(1); // set correct mode
        let bs = 16; // block size
        let mut rpt = Vec::new(); // recovered plaintext
        for i in 0..pt.len() {
            let mut block = vec![0x00 as u8; bs - i%bs - 1]; // set input block
            let c = oracle.encrypt(&block); // query ECB_Oracle(your_string || unknown_string)
            block.extend(rpt.clone()); // prepare input block
            block.push(0x00);
            let l = i/16; // determine current block number
            for j in 0..255 { // guess last byte
                block[16*l+15] = j as u8;
                let d = oracle.encrypt(&block);
                if hex(&c[16*l..16*(l+1)]) == hex(&d[16*l..16*(l+1)]) {
                    rpt.push(j as u8);
                    break;
                }
            }
        }
        assert_eq!(pt,rpt);
    }
}
