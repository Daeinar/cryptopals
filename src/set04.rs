use set02::{pkcs7_pad,pkcs7_unpad,aes128_cbc_encrypt,aes128_cbc_decrypt};
use utils::{random_bytes,store_be_u32,load_be_u32,store_le_u32,load_le_u32};

// test ed25519 ssh key

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
        for i in 0..5 {
            self.state[i] = load_be_u32(&data[4*i..4*(i+1)]);
        }
    }

    pub fn pad(&self, data: &[u8], off: usize) -> Vec<u8> {
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

    // the offset is required for Challenge 29
    pub fn update(&mut self, data: &[u8], off: usize) {

        fn rotl(x: u32, n: usize) -> u32 { (x << n) | (x >> (32 - n)) }

        // pad message
        let m = self.pad(&data, off);

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
            store_be_u32(&mut out[4*i..4*(i+1)], self.state[i]);
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


// note: MD4 uses little endian conversions
pub struct MD4 {
    state: [u32; 4]
}

impl MD4 {

    pub fn new() -> MD4 {
        MD4 { state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476] }
    }

    pub fn reset(&mut self) {
        self.state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];
    }

    pub fn set_state(&mut self, data: &[u8]) {
        for i in 0..4 {
            self.state[i] = load_le_u32(&data[4*i..4*(i+1)]);
        }
    }

    pub fn output(&self, out: &mut[u8]) {
        for i in 0..4 {
            store_le_u32(&mut out[4*i..4*(i+1)], self.state[i]);
        }
    }

    // note: MD4 padding differs slightly from SHA1 padding
    pub fn pad(&self, data: &[u8], off: usize) -> Vec<u8> {
        let l = data.len(); // byte length of input
        let lb = (l + off) * 8; // bit length of input
        let mut m = data.to_vec();
        m.extend(vec![0x00;8+1+(64-(l+off+8+1)%64)%64]);
        let ml = m.len();
        m[l] = 0x80;
        store_le_u32(&mut m[ml-8..ml-4],((lb >>  0) & 0xFFFFFFFF) as u32);
        store_le_u32(&mut m[ml-4..ml-0],((lb >> 32) & 0xFFFFFFFF) as u32);
        m
    }

    pub fn update(&mut self, data: &[u8], off: usize) {

        fn f(x: u32,y: u32,z: u32) -> u32 { (x & y) | ((x ^ 0xFFFFFFFF) & z) }
        fn g(x: u32,y: u32,z: u32) -> u32 { (x & y) | (x & z) | (y & z) }
        fn h(x: u32,y: u32,z: u32) -> u32 { x ^ y ^ z }
        fn rotl(x: u32, n: usize) -> u32 { (x << n) | (x >> (32 - n)) }

        fn ff(a: u32, b: u32, c: u32, d: u32, x: u32, s: usize) -> u32 {
            rotl(a.wrapping_add(f(b,c,d)).wrapping_add(x), s)
        }

        fn gg(a: u32, b: u32, c: u32, d: u32, x: u32, s: usize) -> u32 {
            rotl(a.wrapping_add(g(b,c,d)).wrapping_add(x).wrapping_add(0x5A827999), s)
        }

        fn hh(a: u32, b: u32, c: u32, d: u32, x: u32, s: usize) -> u32 {
            rotl(a.wrapping_add(h(b,c,d)).wrapping_add(x).wrapping_add(0x6ED9EBA1), s)
        }

        // pad message
        let m = self.pad(&data, off);

        let (mut a, mut b, mut c, mut d);
        for mi in m.chunks(64) {
            a = self.state[0];
            b = self.state[1];
            c = self.state[2];
            d = self.state[3];

            let mut x = [0 as u32; 16];
            for i in 0..16 { x[i] = load_le_u32(&mi[4*i..4*(i+1)]); }

            // round 1
            a = ff(a,b,c,d,x[ 0], 3);
            d = ff(d,a,b,c,x[ 1], 7);
            c = ff(c,d,a,b,x[ 2],11);
            b = ff(b,c,d,a,x[ 3],19);

            a = ff(a,b,c,d,x[ 4], 3);
            d = ff(d,a,b,c,x[ 5], 7);
            c = ff(c,d,a,b,x[ 6],11);
            b = ff(b,c,d,a,x[ 7],19);

            a = ff(a,b,c,d,x[ 8], 3);
            d = ff(d,a,b,c,x[ 9], 7);
            c = ff(c,d,a,b,x[10],11);
            b = ff(b,c,d,a,x[11],19);

            a = ff(a,b,c,d,x[12], 3);
            d = ff(d,a,b,c,x[13], 7);
            c = ff(c,d,a,b,x[14],11);
            b = ff(b,c,d,a,x[15],19);

            // round 2
            a = gg(a,b,c,d,x[ 0], 3);
            d = gg(d,a,b,c,x[ 4], 5);
            c = gg(c,d,a,b,x[ 8], 9);
            b = gg(b,c,d,a,x[12],13);

            a = gg(a,b,c,d,x[ 1], 3);
            d = gg(d,a,b,c,x[ 5], 5);
            c = gg(c,d,a,b,x[ 9], 9);
            b = gg(b,c,d,a,x[13],13);

            a = gg(a,b,c,d,x[ 2], 3);
            d = gg(d,a,b,c,x[ 6], 5);
            c = gg(c,d,a,b,x[10], 9);
            b = gg(b,c,d,a,x[14],13);

            a = gg(a,b,c,d,x[ 3], 3);
            d = gg(d,a,b,c,x[ 7], 5);
            c = gg(c,d,a,b,x[11], 9);
            b = gg(b,c,d,a,x[15],13);

            // round 3
            a = hh(a,b,c,d,x[ 0], 3);
            d = hh(d,a,b,c,x[ 8], 9);
            c = hh(c,d,a,b,x[ 4],11);
            b = hh(b,c,d,a,x[12],15);

            a = hh(a,b,c,d,x[ 2], 3);
            d = hh(d,a,b,c,x[10], 9);
            c = hh(c,d,a,b,x[ 6],11);
            b = hh(b,c,d,a,x[14],15);

            a = hh(a,b,c,d,x[ 1], 3);
            d = hh(d,a,b,c,x[ 9], 9);
            c = hh(c,d,a,b,x[ 5],11);
            b = hh(b,c,d,a,x[13],15);

            a = hh(a,b,c,d,x[ 3], 3);
            d = hh(d,a,b,c,x[11], 9);
            c = hh(c,d,a,b,x[ 7],11);
            b = hh(b,c,d,a,x[15],15);

            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
        }
    }

    pub fn mac_update(&mut self, key: &[u8], data: &[u8]) {
        let mut combined = key.to_vec();
        combined.extend(data.to_vec());
        self.update(&combined, 0);
    }

    pub fn mac_verify(&mut self, key: &[u8], data: &[u8], t0: &[u8]) -> u8 {
        let mut t1 = [0x00 as u8; 16];
        self.mac_update(key, data);
        self.output(&mut t1);
        let mut result: u8 = 0;
        for i in 0..16 {
            result |= t0[i] ^ t1[i];
        }
        result
    }
}


pub struct MD4Oracle { key: Vec<u8>, md4: MD4 }

impl MD4Oracle {
    pub fn new() -> MD4Oracle {
        MD4Oracle { key: random_bytes(16), md4: MD4::new() }
    }
    pub fn digest(&mut self, out: &mut[u8], data: &[u8]) {
        self.md4.reset();
        self.md4.mac_update(&self.key, &data);
        self.md4.output(out);
    }
    pub fn verify(&mut self, data: &[u8], tag: &[u8]) -> bool {
        self.md4.reset();
        if self.md4.mac_verify(&self.key, data, tag) == 0 {
            return true;
        }
        false
    }
}

