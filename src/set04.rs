use set02::{pkcs7_pad,pkcs7_unpad,aes128_cbc_encrypt,aes128_cbc_decrypt};
use utils::{random_bytes,store_be_u32,load_be_u32};

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

pub struct SHA1 {
    state: [u32; 5]
}

impl SHA1 {

    pub fn new() -> SHA1 {
        SHA1 { state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0] }
    }

    pub fn reset(&mut self) {
        self.state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    }

    pub fn set_state(&mut self, data: &[u8]) {
        self.state[0] = load_be_u32(&data[ 0.. 4]);
        self.state[1] = load_be_u32(&data[ 4.. 8]);
        self.state[2] = load_be_u32(&data[ 8..12]);
        self.state[3] = load_be_u32(&data[12..16]);
        self.state[4] = load_be_u32(&data[16..20]);
    }

    // the offset is required for Challenge 29
    pub fn update(&mut self, data: &[u8], off: usize) {

        fn rotl(x: u32, n: usize) -> u32 {
            (x << n) | (x >> (32 - n))
        }

        // pad message
        let l = data.len(); // byte length of input
        let lb = (l + off) * 8; // bit length of input
        let mut m = data.to_vec();
        m.extend(vec![0x00;8+1+(64-(l+off+8+1)%64)%64]);
        let ml = m.len();
        m[l] = 0x80;
        store_be_u32(&mut m[ml-8..ml-4],((lb >> 32) & 0xFFFFFFFF) as u32);
        store_be_u32(&mut m[ml-4..ml-0],((lb >>  0) & 0xFFFFFFFF) as u32);

        let mut words = [0 as u32; 80];
        let (mut a, mut b, mut c, mut d, mut e);
        for mi in m.chunks(64) {
            a = self.state[0];
            b = self.state[1];
            c = self.state[2];
            d = self.state[3];
            e = self.state[4];
            for t in 0..80 {
                let (k,f) = match t {
                     0...19 => (0x5A827999, (b & c) | ((b ^ 0xFFFFFFFF) & d)),
                    20...39 => (0x6ED9EBA1, b ^ c ^ d),
                    40...59 => (0x8F1BBCDC, (b & c) | (b & d) | (c & d)),
                    60...79 => (0xCA62C1D6, b ^ c ^ d),
                          _ => (0,0)
                };
                words[t] = match t {
                     0...15 => load_be_u32(&mi[4*t..4*(t+1)]),
                    16...79 => rotl(words[t-3] ^ words[t-8] ^ words[t-14] ^ words[t-16], 1),
                          _ => 0
                };
                let tmp = rotl(a,5).wrapping_add(f)
                                   .wrapping_add(e)
                                   .wrapping_add(words[t])
                                   .wrapping_add(k);
                e = d;
                d = c;
                c = rotl(b, 30);
                b = a;
                a = tmp;
            }
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
        }
    }

    pub fn mac_update(&mut self, key: &[u8], data: &[u8]) {
        let mut combined = key.to_vec();
        combined.extend(data.to_vec());
        self.update(&combined, 0);
    }

    pub fn mac_verify(&mut self, key: &[u8], data: &[u8], t0: &[u8]) -> u8 {
        let mut t1 = [0x00 as u8; 20];
        self.mac_update(key, data);
        self.output(&mut t1);
        let mut result: u8 = 0;
        for i in 0..20 {
            result |= t0[i] ^ t1[i];
        }
        result
    }

    pub fn output(&self, out: &mut[u8]) {
        for i in 0..5 {
            store_be_u32(&mut out[4*i..4*i+4], self.state[i]);
        }
    }

}


pub struct SHA1Oracle { key: Vec<u8>, sha1: SHA1 }

impl SHA1Oracle {
    pub fn new() -> SHA1Oracle {
        SHA1Oracle { key: random_bytes(16), sha1: SHA1::new() }
    }
    pub fn digest(&mut self, out: &mut[u8], data: &[u8]) {
        self.sha1.reset();
        self.sha1.mac_update(&self.key, &data);
        self.sha1.output(out);
    }
    pub fn verify(&mut self, data: &[u8], tag: &[u8]) -> bool {
        self.sha1.reset();
        if self.sha1.mac_verify(&self.key, data, tag) == 0 {
            return true;
        }
        false
    }
}

// for glue padding
pub fn md_pad(data: &[u8], off: usize) -> Vec<u8> {
    let l = data.len(); // byte length of input
    let lb = (l + off) * 8; // bit length of input
    let mut m = data.to_vec();
    m.extend(vec![0x00;8+1+(64-(l+off+8+1)%64)%64]);
    let ml = m.len();
    m[l] = 0x80;
    store_be_u32(&mut m[ml-8..ml-4],((lb >> 32) & 0xFFFFFFFF) as u32);
    store_be_u32(&mut m[ml-4..ml-0],((lb >>  0) & 0xFFFFFFFF) as u32);
    m
}

