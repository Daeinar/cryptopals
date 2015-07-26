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

    pub fn set_state(&mut self, a: u32, b: u32, c: u32, d: u32, e: u32) {
        self.state[0] = a;
        self.state[1] = b;
        self.state[2] = c;
        self.state[3] = d;
        self.state[4] = e;
    }

    pub fn update(&mut self, data: &[u8]) {

        fn rotl(x: u32, n: usize) -> u32 {
            (x << n) | (x >> (32 - n))
        }

        // pad message
        let l = data.len(); // byte length of input
        let lb = l * 8; // bit length of input
        let mut m = data.to_vec();
        m.extend(vec![0x00;8+1+(64-(l+8+1)%64)%64]);
        let ml = m.len();
        m[l] = 0x80;
        store_be_u32(&mut m[ml-8..ml-4],((lb >> 32) & 0xFFFFFFFF) as u32);
        store_be_u32(&mut m[ml-4..ml-0],((lb >>  0) & 0xFFFFFFFF) as u32);

        let mut words = [0 as u32; 80];
        //let mut h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        for mi in m.chunks(64) {
            let mut a = self.state[0];
            let mut b = self.state[1];
            let mut c = self.state[2];
            let mut d = self.state[3];
            let mut e = self.state[4];
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
        self.update(&combined);
    }

    pub fn output(&self, out: &mut[u8]) {
        for i in 0..5 {
            store_be_u32(&mut out[4*i..4*i+4], self.state[i]);
        }
    }

}
