#[cfg(test)]
mod test {

    use set01::{hex};
    use set04::{sha1_mac};

    #[test]
    fn test_c28() {

        let key = b"abc";
        let msg = b"";
        assert_eq!(hex(&sha1_mac(key,msg)),"a9993e364706816aba3e25717850c26c9cd0d89d");

        let key = b"";
        let msg = b"";
        assert_eq!(hex(&sha1_mac(key,msg)),"da39a3ee5e6b4b0d3255bfef95601890afd80709");

        let key = b"";
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(hex(&sha1_mac(key,msg)),"84983e441c3bd26ebaae4aa1f95129e5e54670f1");

    }
}
