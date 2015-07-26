#[cfg(test)]
mod test {

    extern crate openssl;
    use set01::{hex};
    use set04::{SHA1};
    use self::openssl::crypto::hash::{hash, Type};

    #[test]
    fn test_c28() {

        let mut sha1 = SHA1::new();
        let mut out = [0x00 as u8; 20];
        let mut msg = [0x00 as u8; 512];
        for i in 0..512 {
            msg[i] = (i & 0xFF) as u8;
            sha1.reset();
            sha1.update(&msg[0..i+1]);
            sha1.output(&mut out);
            assert_eq!(hex(&out),hex(&hash(Type::SHA1,&msg[0..i+1])));
        }

    }
}
