extern crate rand;

use std::collections::HashMap;
use self::rand::{thread_rng, Rng};
use set01::{hex,xor,aes128_ecb_encrypt,aes128_ecb_decrypt,is_ecb_ciphertext};
use utils::{random_bytes};

pub fn pkcs7(x: &[u8], n: usize) -> Vec<u8> {
    vec![x.to_vec(),vec![((n-x.len()%n)) as u8; ((n-x.len()%n))]].concat()
}

pub fn remove_pkcs7(x: &[u8], n: usize) -> Vec<u8> {
    assert!(x.len()%n == 0);
    let l = x[x.len()-1] as usize;
    for i in 0..l {
        if l != x[x.len()-1-i] as usize {
            panic!("invalid padding");
        }
    }
    x[0..(x.len()-l as usize)].to_vec()
}

pub fn aes128_cbc_encrypt(k: &[u8], iv: &[u8], m: &[u8]) -> Vec<u8> {
    assert!(k.len() == 16 && iv.len() == 16 && m.len()%16 == 0);
    let mut c = vec![];
    if m.len() > 0 {
        c.extend(aes128_ecb_encrypt(k, &xor(iv, &m[0..16])));
        for i in 1..m.len()/16 {
            let b = xor(&c[16*(i-1)..16*i], &m[16*i..16*(i+1)]);
            c.extend(aes128_ecb_encrypt(k, &b));
        }
    }
    c
}

pub fn aes128_cbc_decrypt(k: &[u8], iv: &[u8], c: &[u8]) -> Vec<u8> {
    assert!(k.len() == 16 && iv.len() == 16 && c.len()%16 == 0);
    let mut m = vec![];
    if c.len() > 0 {
        m.extend(xor(iv,&aes128_ecb_decrypt(k, &c[0..16])));
        for i in 1..c.len()/16 {
            m.extend(xor(&c[16*(i-1)..16*i],&aes128_ecb_decrypt(k, &c[16*i..16*(i+1)])));
        }
    }
    m
}

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
            aes128_ecb_encrypt(&k, &m)
            },
        false => {
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

pub fn parse_profile(s: &str) -> HashMap<&str,&str> {
    let v: Vec<&str> = s.split('&').collect();
    let mut hmap = HashMap::new();
    for x in v {
        let t: Vec<&str> = x.split('=').collect();
        hmap.insert(t[0], t[1]);
    }
    hmap
}

pub fn get_profile(s :&str) -> String {
    vec!["email=",&s.replace("=","").replace("&",""),"&uid=10&role=user"].concat()
}

pub struct CBCOracle { key: Vec<u8> }

impl CBCOracle {
pub fn new() -> CBCOracle {
    CBCOracle { key: random_bytes(16) }
    }
    pub fn encrypt(&self, iv: &[u8], m: &[u8]) -> Vec<u8> {
        aes128_cbc_encrypt(&self.key, &iv, &pkcs7(&m,16))
    }
    pub fn decrypt(&self, iv: &[u8], c: &[u8] ) -> Vec<u8> {
        remove_pkcs7(&aes128_cbc_decrypt(&self.key, &iv, &c),16)
    }
}

pub fn create_message(prefix: &str, msg: &str, suffix: &str) -> String {
    vec![prefix,msg,suffix].concat().replace(";","\";\"").replace("=","\"=\"")
}

pub fn contains_string(s: &str, t: &str) -> bool {
    let x = s.to_string();
    match x.find(t) {
        None => false,
        _ => true
    }
}
