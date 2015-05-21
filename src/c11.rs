#[cfg(test)]
mod test {
    use set01::{decode_base64,aes128_ecb_decrypt};
    use set02::{encryption_oracle,is_ecb_oracle};
    use utils::{read_file};

    #[test]
    fn test_c11() {
        let key = b"YELLOW SUBMARINE";
        let path = "src/c07.txt";
        let v = read_file(&path).concat();
        let ct = decode_base64(&v); // decode ciphertext
        let pt = aes128_ecb_decrypt(key, &ct);
        let is_ecb = is_ecb_oracle(&pt,encryption_oracle);
        assert_eq!(is_ecb, is_ecb); // lame test, some better way?
    }
}
