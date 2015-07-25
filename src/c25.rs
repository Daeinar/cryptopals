#[cfg(test)]
mod test {

    use set01::{decode_base64,aes128_ecb_decrypt};
    use set03::{CTROracle};
    use utils::{read_file};

    #[test]
    fn test_c25() {

        let path ="src/c25.txt";
        let v = read_file(&path).concat();

        let key = b"YELLOW SUBMARINE";
        let ct = decode_base64(&v);
        let pt = aes128_ecb_decrypt(key, &ct);

        let oracle = CTROracle::new();
        let nonce = [0x00; 8];

        let l = 81; // #recovered bytes

        let c = oracle.encrypt(&nonce, &pt[0..l]);

        let mut x = vec![0x00; c.len()]; // recovered plaintext

        for off in 0..c.len() {
            for b in 0..256 {
                x[off] = b as u8;
                let d = oracle.edit(&c, &nonce, &x[0..off+1], 0);
                if c[off] == d[off] {
                    break;
                }
            }
        }
        assert_eq!(String::from_utf8(pt[0..l].to_vec()).unwrap(),String::from_utf8(x).unwrap());
    }
}
