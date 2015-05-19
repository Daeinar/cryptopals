#[cfg(test)]
mod test {
    use c01::{decode_base64,hex};
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
        let mut num_padding_bytes = 15;
        for i in 1..16 {
            let y = oracle.encrypt(&vec![0x00 as u8; i]);
            if l != y.len() {
                num_padding_bytes = i - 1;
                break;
            }
        }
        // compute number of random bytes
        let nrb = x.len() - pt.len() - num_padding_bytes;

        let bs = 16; // block size
        let mut rpt = Vec::new(); // recovered plaintext
        for i in 0..pt.len() {
            let mut block = vec![0x00 as u8; (bs - nrb%bs) + (bs - i%bs - 1)]; // set input block including compensation for random byte offset
            let c = oracle.encrypt(&block); // query ECB_Oracle(random_prefix || your_input || unknown_suffix)
            block.extend(rpt.clone()); // prepare input block
            block.push(0x00);
            let bn = i/bs; // determin current block number
            for j in 0..255 { // guess last byte
                block[(bs - nrb%bs) + (bs*bn + bs - 1)] = j as u8;
                let d = oracle.encrypt(&block);
                let o = (nrb + (bs - nrb%bs) + i)/bs; // determine offset in ciphertext
                if hex(&c[bs*o..bs*(o+1)]) == hex(&d[bs*o..bs*(o+1)]) {
                    rpt.push(j as u8);
                    break;
                }
            }
        }
        assert_eq!(pt,rpt);
    }
}
