#[cfg(test)]
mod test {
    use set01::{decode_base64,aes128_ecb_encrypt,aes128_ecb_decrypt};
    use utils::{read_file};

    #[test]
    fn test_c07() {
        let key = b"YELLOW SUBMARINE";
        let path = "src/c07.txt";
        let v = read_file(&path).concat();
        let ct = decode_base64(&v); // decode ciphertext
        assert_eq!(&ct, &aes128_ecb_encrypt(key, &aes128_ecb_decrypt(key, &ct)));
    }
}
