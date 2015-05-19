use c01::{hex,random_bytes};
use c07::{aes128_ecb_encrypt,aes128_ecb_decrypt};
use c09::pkcs7;

pub struct ECBOracle { key: Vec<u8>, prefix: Vec<u8>, suffix: Vec<u8>, mode: usize } // msg is an "unknown" string and appended at each query before encryption

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


pub fn attack_ecb(oracle: ECBOracle, length: usize, block_size: usize, num_random_bytes: usize, offset: usize) -> Vec<u8> {

    let mut recovered_pt = Vec::new(); // recovered plaintext
    for i in 0..length {
        let mut block = vec![0x00 as u8; offset + (block_size - i % block_size - 1)]; // set input block including compensation for random byte offset
        let c = oracle.encrypt(&block); // query ECB_Oracle(random_prefix || your_input || unknown_suffix)
        block.extend(recovered_pt.clone()); // prepare input block
        block.push(0x00);
        let block_number = i/block_size;
        for j in 0..255 { // guess last byte
            block[offset + (block_size*block_number + block_size - 1)] = j as u8;
            let d = oracle.encrypt(&block);
            let o = (num_random_bytes + offset + i)/block_size; // determine offset in ciphertext
            if hex(&c[block_size*o..block_size*(o+1)]) == hex(&d[block_size*o..block_size*(o+1)]) {
                recovered_pt.push(j as u8);
                break;
            }
        }
    }
    recovered_pt
}


#[cfg(test)]
mod test {
    use c01::decode_base64;
    use c12::*;

    #[test]
    fn test_c12() {
        let pt = decode_base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        let mut oracle = ECBOracle::new(); // init ECB oracle
        oracle.set_suffix(&pt); // set "unknown" plaintext suffix
        oracle.set_mode(1); // set correct mode
        assert_eq!(pt, attack_ecb(oracle, pt.len(), 16, 0, 0));
    }
}
