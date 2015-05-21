#[cfg(test)]
mod test {
    use set01::{decode_base64,read_file,aes128_ecb_encrypt,aes128_ecb_decrypt};

    #[test]
    fn test_c07() {
        let key = b"YELLOW SUBMARINE";
        let path = "src/c07.txt";
        let v = read_file(&path).concat();
        let ct = decode_base64(&v); // decode ciphertext
        assert_eq!(&ct, &aes128_ecb_encrypt(key, &aes128_ecb_decrypt(key, &ct)));
    }
}
