#[cfg(test)]
mod test {

    use set02::{pkcs7_unpad,aes128_cbc_decrypt};
    use set04::{CBCOracleKeyIV,is_ascii};

    #[test]
    fn test_c27() {
        let msg = "The thing's hollow, it goes on forever and oh my God! It's full of stars!";
        // use oracle to encrypt under unknown key
        let oracle = CBCOracleKeyIV::new();
        let c = oracle.encrypt(&msg.as_bytes());
        // modify ciphertext
        let mut d = c.clone();
        for i in 0..16 {
            d[16 + i] = 0x00;
            d[32 + i] = d[i];
        }
        // use oracle to decrypt modified ciphertext under unknown key
        let p = oracle.decrypt(&d).unwrap();
        if !is_ascii(&p) {
            // recover secret key
            let mut k = vec![0x00; 16];
            for i in 0..16 {
                k[i] = p[i] ^ p[i + 32];
            }
            let m = pkcs7_unpad(&aes128_cbc_decrypt(&k, &k, &c),16).unwrap();
            assert_eq!(msg,String::from_utf8(m).unwrap());
        }
    }
}
