#[cfg(test)]
mod test {

    use set02::{create_message,contains_string};
    use set03::{CTROracle};

    #[test]
    fn test_c26() {
        let oracle = CTROracle::new();
        let nonce = [0x00; 8];
        let prefix = "comment1=cooking%20MCs;userdata=";
        let msg = "FOOBAR!!;admin=true";
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
        let s = create_message(prefix,msg,suffix);
        let mut c = oracle.encrypt(&nonce, &s.as_bytes());
        c[48] ^= b'"' ^ b';';
        c[54] ^= b'"' ^ b'=';
        c[55] ^= b'=' ^ b't';
        c[56] ^= b'"' ^ b'r';
        c[57] ^= b't' ^ b'u';
        c[58] ^= b'r' ^ b'e';
        c[59] ^= b'u' ^ b';';
        let p = oracle.encrypt(&nonce, &c);
        assert_eq!(true,contains_string(&String::from_utf8(p).unwrap(),";admin=true;"));
    }
}
