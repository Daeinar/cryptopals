#[cfg(test)]
mod test {
    use set02::{CBCOracle,pkcs7_unpad};
    use set03::{recover_cbc_plaintext};
    use utils::{random_u32};

    #[test]
    fn test_c17() {
        let s = vec!["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                     "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                     "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                     "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                     "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                     "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                     "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                     "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                     "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                     "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"];
        let oracle = CBCOracle::new();
        let t = (random_u32() % 10) as usize;
        let iv = vec![0x00; 16];
        let st = s[t].as_bytes();
        let c = oracle.encrypt(&iv,&st);
        let p = pkcs7_unpad(&recover_cbc_plaintext(&oracle, &iv, &c),16);
        assert_eq!(s[t],String::from_utf8(p.unwrap()).unwrap());
    }

}
