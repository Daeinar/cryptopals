#[cfg(test)]
mod test {
    use c01::decode_base64;
    use c12::*;

    #[test]
    fn test_c14() {
        let pt = decode_base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        let mut oracle = ECBOracle::new();
        oracle.set_suffix(&pt);
        oracle.set_mode(2);

        // detect number of padding bytes
        let x = oracle.encrypt(&vec![]);
        let l = x.len();
        let mut num_padding_bytes = 16;
        for i in 0..16 {
            let y = oracle.encrypt(&vec![0x00 as u8; i]);
            if l != y.len() {
                num_padding_bytes = i;
                break;
            }
        }
        // compute number of random bytes
        let num_random_bytes = x.len() - pt.len() - num_padding_bytes;
        // block size
        let block_size = 16;
        // offset to compensate random bytes
        let offset = block_size - num_random_bytes % block_size;
        assert_eq!(pt, attack_ecb(oracle, pt.len(), block_size, num_random_bytes, offset));
    }
}
