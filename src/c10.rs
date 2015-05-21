#[cfg(test)]
mod test {
    use set01::{decode_base64};
    use set02::{aes128_cbc_encrypt,aes128_cbc_decrypt};
    use utils::{read_file};

    #[test]
    fn test_c10() {
        let key = b"YELLOW SUBMARINE";
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let path = "src/c10.txt";
        let v = read_file(&path).concat();
        let ct = decode_base64(&v);
        let pt = aes128_cbc_decrypt(key, iv, &ct);
        assert_eq!(ct, aes128_cbc_encrypt(key, iv, &pt));
    }
}
