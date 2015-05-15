use c02::*;
use c07::*;

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
