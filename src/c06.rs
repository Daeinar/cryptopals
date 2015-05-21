#[cfg(test)]
mod test {
    use set01::{encode_base64,decode_base64,read_file,hamming_distance,analyse_vigenere};

    #[test]
    fn test_c06() {
        let x = "this is a test";
        let y = "wokka wokka!!!";
        assert_eq!(37, hamming_distance(&x.as_bytes(),&y.as_bytes()));
        assert_eq!(x,String::from_utf8(decode_base64(&encode_base64(&x.as_bytes()))).unwrap()); // test base64 encoding and decoding
        let path = "src/c06.txt";
        let v = read_file(&path).concat();
        let ct = decode_base64(&v); // decode ciphertext
        let key = analyse_vigenere(&ct); // steps 3 to 8
        assert_eq!(&key, &vec![0x74, 0x45, 0x52, 0x4D, 0x49, 0x4E,
                               0x41, 0x54, 0x4F, 0x52, 0x00, 0x78,
                               0x1A, 0x00, 0x62, 0x52, 0x49, 0x4E,
                               0x47, 0x00, 0x54, 0x48, 0x45, 0x00,
                               0x4E, 0x4F, 0x49, 0x53, 0x45]);
    }
}
