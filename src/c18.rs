#[cfg(test)]
mod test {
    use set01::{ascii,decode_base64};
    use set03::aes128_ctr;

    #[test]
    fn test_c18() {
        let c = decode_base64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
        let k = b"YELLOW SUBMARINE";
        let n = b"\x00\x00\x00\x00\x00\x00\x00\x00";
        let m = aes128_ctr(n,k,&c);
        assert_eq!("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", String::from_utf8(ascii(&m)).unwrap());
    }
}
