use set01::{xor,aes128_ecb_encrypt};
use set02::CBCOracle;
use utils::{random_bytes,store64,add32,mult32};


fn recover_cbc_byte(oracle: &CBCOracle, block: &[u8], iv: &[u8], c: &[u8], i: usize, o: usize, t: bool) -> Vec<Vec<u8>> {
    let mut blocks = vec![];
    let mut x = iv.to_vec();
    let mut y = match t { true => c[0..o].to_vec(), false => c[0..16].to_vec(), };
    for j in 0..256 {
        if t {
            // modify ciphertext
            for k in 0..i {
                y[o - 16 - (k + 1)] = c[o - 16 - (k + 1)] ^ block[16 - (k + 1)] ^ ((i + 1) as u8);
            }
            y[o - 16 - (i + 1)] = c[o - 16 - (i + 1)] ^ (j as u8) ^ ((i + 1) as u8);
        } else {
            // modify IV
            for k in 0..i {
                x[o - 16 - (k + 1)] = iv[o - 16 - (k + 1)] ^ block[16 - (k + 1)] ^ ((i + 1) as u8);
            }
            x[o - 16 - (i + 1)] = iv[o - 16 - (i + 1)] ^ (j as u8) ^ ((i + 1) as u8);
        }
        if None != oracle.decrypt(&x, &y) {
            let mut b = block.to_vec();
            b[16 - i - 1] = j as u8;
            blocks.push(b);
        }
    }
    blocks
}

pub fn recover_cbc_plaintext(oracle: &CBCOracle, iv: &[u8], c: &[u8]) -> Vec<u8> {
    let mut p = vec![];
    // prepare block offset list
    let mut v = (0..(c.len()/16-1)).map(|i| (c.len() - 16*i, true) ).collect::<Vec<(usize,bool)>>();
    v.push((32, false)); // in the last step we have to modify the IV instead of the ciphertext
    for (o,t) in v {
        let mut blocks = vec![];
        for i in 0..16 {
            blocks = match i {
                0 => recover_cbc_byte(&oracle, &vec![0x00;16], &iv, &c, i, o, t),
                _ => {
                    let mut buffer = vec![];
                    for b in blocks {
                        buffer.extend(recover_cbc_byte(&oracle, &b, &iv, &c, i, o, t));
                    }
                    buffer
                }
            }
        }
        // there was not a single case where more than one block was left at this point
        p.insert(0,blocks[0].to_vec());
    }
    p.concat()
}

pub fn aes128_ctr(n: &[u8], k: &[u8], m: &[u8]) -> Vec<u8> {
    let mut i = 0;
    let nonce = n.to_vec();
    let mut c = vec![];
    for x in m.chunks(16) {
        let y = vec![nonce.clone(),store64(i as u64)].concat();
        c.extend(xor(x,&aes128_ecb_encrypt(k,&y)[0..x.len()]));
        i += 1;
    }
    c
}

pub struct CTROracle{ key: Vec<u8> }

impl CTROracle {
    pub fn new() -> CTROracle {
        CTROracle { key: random_bytes(16) }
    }
    pub fn encrypt(&self, n: &[u8], m: &[u8]) -> Vec<u8> {
        aes128_ctr(&n, &self.key, &m)
    }
}

// returns elements of x contained in f
fn filter_elements(x: &[u8], f: &[u8]) -> Vec<u8> {
    x.iter().map(|y| y.clone()).filter(|&y| f.contains(&y)).collect::<Vec<u8>>()
}

pub fn attack_ctr(c: &Vec<Vec<u8>>, filter_a: &[u8], filter_b: &[u8]) -> Vec<Vec<u8>> {

    let min_l = c.iter().map(|x| x.len()).min().unwrap(); // find minimum of ciphertext lengths

    // recovered plaintext
    let mut p: Vec<Vec<u8>> = vec![ vec![0x5F; min_l]; c.len() ]; // 0x5F == b'_' used to easily spot missing columns

    for i in 0..min_l {
        let mut candidates = vec![];

        // guess stream bytes and apply filter_a
        for byte in 0..256 {
            let column = (0..c.len()).map(|j| c[j][i]).collect::<Vec<u8>>(); // get column
            let guess = xor(&column,&vec![byte as u8; c.len()]);
            if c.len() == filter_elements(&guess,&filter_a).len() {
                candidates.push(guess);
            }
        }
        let x = match candidates.len() {
            0 => panic!("no candidates found"),
            1 => candidates.pop().unwrap(),
            _ => {
                  // find candidate that contains the most elements with respect to filter_b
                  let t = (0..candidates.len()).map(|j| (filter_elements(&candidates[j],&filter_b).len(),j)).max().unwrap();
                  candidates[t.1].clone()
            }
        };
        // copy elements from the most promising candidate x to the correct position in the plaintext
        for k in 0..x.len() {
            p[k][i] = x[k];
        }
    }
    p
}

pub struct MT19937{ mt: [u32; 624], index: usize }

impl MT19937 {
    pub fn new() -> MT19937 {
        MT19937 { mt: [0; 624], index: 0 }
    }
    pub fn seed(&mut self, seed: u32) {
        self.index = 0;
        self.mt[0] = seed;
        for i in 1..624 {
            self.mt[i] = add32(mult32(0x6C078965, self.mt[i-1] ^ (self.mt[i-1] >> 30)), i as u32);
        }
    }
    fn generate_numbers(&mut self) {
        for i in 0..624 {
            let y = add32(self.mt[i] & 0x80000000, self.mt[ (i+1) % 624 ] & 0x7FFFFFFF);
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1);
            if y % 2 != 0 {
                self.mt[i]  = self.mt[i] ^ 0x9908B0DF
            }
        }
    }
    pub fn generate_random_u32(&mut self) -> u32 {
        if self.index == 0 {
            self.generate_numbers();
        }
        let y = self.temper(self.mt[self.index]);
        self.index = (self.index + 1) % 624;
        y
    }
    pub fn temper(&self, x: u32) -> u32 {
        let mut y = x ^ (x >> 11);
        y = y ^ ((y << 7) & 0x9D2C5680);
        y = y ^ ((y << 15) & 0xEFC60000);
        y ^ (y >> 18)
    }
    pub fn set_state(&mut self, x: &[u32]) {
        assert!(x.len() == 624);
        for i in 0..624 {
            self.mt[i] = x[i];
        }
    }
}

pub fn untemper(x: u32) -> u32 {
    let mut y = x ^ (x >> 18);
    y = y ^ ((y << 15) & 0xEFC60000);
    y = y ^ ((y << 7) & 0x9D2C5680) ^ ((y << 14) & 0x94284000) ^ ((y << 21) & 0x14200000) ^ ((y << 28) & 0x10000000);
    y ^ (y >> 11) ^ (y >> 22)
}


pub struct MT19937Oracle { key: [u8; 2], prefix: Vec<u8>, rng: MT19937 }

impl MT19937Oracle {
    pub fn new() -> MT19937Oracle {
           MT19937Oracle { key: [0x00,0x00], prefix: random_bytes(random_bytes(1)[0] as usize), rng: MT19937::new() }
    }
    pub fn init(&mut self) {
        let k = random_bytes(2);
        self.key[0] = k[0];
        self.key[1] = k[1];
        self.rng.seed( ((k[1] as u32) << 8) | (k[0] as u32) );
    }
    pub fn encrypt(&mut self, m: &[u8]) -> Vec<u8> {
        let mut c = vec![];
        let n = vec![self.prefix.clone(),m.to_vec()].concat();
        for x in n.chunks(4) {
            let s = self.rng.generate_random_u32();
            let r = [ (s >> 0) as u8, (s >> 8) as u8, (s >> 16) as u8, (s >> 24) as u8];
            c.extend(xor(x,&r[0..x.len()]));
        }
        c
    }
}

