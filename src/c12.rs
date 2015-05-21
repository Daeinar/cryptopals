#[cfg(test)]
mod test {
    use set01::{decode_base64};
    use set02::{ECBOracle,attack_ecb};

    #[test]
    fn test_c12() {
        let pt = decode_base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        let mut oracle = ECBOracle::new(); // init ECB oracle
        oracle.set_suffix(&pt); // set "unknown" plaintext suffix
        oracle.set_mode(1); // set correct mode
        assert_eq!(pt, attack_ecb(oracle, pt.len(), 16, 0, 0));
    }
}
