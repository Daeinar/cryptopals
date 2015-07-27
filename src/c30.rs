#[cfg(test)]
mod test {

    use set01::{hex};
    use set04::{MD4, MD4Oracle};

    #[test]
    fn test_c30() {

        // run some test vectors
        let mut tag = [0x00 as u8; 16];
        let mut md4 = MD4::new();
        let msg = b"";
        md4.update(msg, 0);
        md4.output(&mut tag);
        assert_eq!("31d6cfe0d16ae931b73c59d7e0c089c0", hex(&tag));

        let msg = b"The quick brown fox jumps over the lazy dog";
        md4.reset();
        md4.update(msg, 0);
        md4.output(&mut tag);
        assert_eq!("1bee69a46ba811185c194762abaeae90", hex(&tag));

        let msg = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        md4.reset();
        md4.update(msg, 0);
        md4.output(&mut tag);
        assert_eq!("043f8582f241db351ce627e153e7f0e4", hex(&tag));

        // run the forgery attack
        let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let suffix = b";admin=true";
        let mut tag = [0x00 as u8; 16];
        let mut oracle = MD4Oracle::new();
        oracle.digest(&mut tag, msg);

        // init md4 state with tag
        let mut md4 = MD4::new();
        md4.set_state(&tag);

        // set key byte offset (see MD4Oracle; if not known just bruteforce it) and forge message
        let key_off = 16;
        let mut forged_msg = md4.pad(msg, key_off);
        let max_off = forged_msg.len() + key_off;
        forged_msg.extend(suffix.to_vec());

        // forge tag
        let mut forged_tag = [0x00 as u8; 16];
        md4.update(suffix, max_off);
        md4.output(&mut forged_tag);

        // query oracle for verification
        assert!(oracle.verify(&forged_msg, &forged_tag));
    }
}
