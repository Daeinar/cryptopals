#[cfg(test)]
mod test {

    use set04::{SHA1, SHA1Oracle, md_pad};

    #[test]
    fn test_c29() {

        let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let suffix = b";admin=true";
        let mut tag = [0x00 as u8; 20];
        let mut oracle = SHA1Oracle::new();
        oracle.digest(&mut tag, msg);

        // init sha1 state with tag
        let mut sha1 = SHA1::new();
        sha1.set_state(&tag);

        // set key byte offset (if not known just bruteforce it) and forge message
        let key_off = 16;
        let mut forged_msg = md_pad(msg, key_off);
        let max_off = forged_msg.len() + key_off;
        forged_msg.extend(suffix.to_vec());

        // forge tag
        let mut forged_tag = [0x00 as u8; 20];
        sha1.update(suffix, max_off);
        sha1.output(&mut forged_tag);

        // query oracle for verification
        assert!(oracle.verify(&forged_msg, &forged_tag));
    }
}
