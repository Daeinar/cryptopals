extern crate openssl;

use self::openssl::crypto::symm as cipher;

pub fn aes128_ecb_encrypt(k: &[u8], m: &[u8]) -> Vec<u8> {
    assert!(k.len() == 16 && m.len()%16 == 0);
    let aes = cipher::Crypter::new(cipher::Type::AES_128_ECB);
    aes.init(cipher::Mode::Encrypt, k, vec![]);
    aes.pad(false);
    m.chunks(16).map(|x| aes.update(x)).collect::<Vec<Vec<u8>>>().concat()
}

pub fn aes128_ecb_decrypt(k: &[u8], c: &[u8]) -> Vec<u8> {
    assert!(k.len() == 16 && c.len()%16 == 0);
    let aes = cipher::Crypter::new(cipher::Type::AES_128_ECB);
    aes.init(cipher::Mode::Decrypt, k, vec![]);
    aes.pad(false);
    c.chunks(16).map(|x| aes.update(x)).collect::<Vec<Vec<u8>>>().concat()
}


#[cfg(test)]
mod test {
    use c01::decode_base64;
    use c04::read_file;
    use c07::*;

    #[test]
    fn test_c07() {
        let key = b"YELLOW SUBMARINE";
        let path = "src/c07.txt";
        let v = read_file(&path).concat();
        let ct = decode_base64(&v); // decode ciphertext
        assert_eq!(&ct, &aes128_ecb_encrypt(key, &aes128_ecb_decrypt(key, &ct)));
    }
}
