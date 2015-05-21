#[cfg(test)]
mod test {
    use set02::{pkcs7,remove_pkcs7};

    #[test]
    fn test_c15a() {
        let s = "ICE ICE BABY\x04\x04\x04\x04";
        let t = remove_pkcs7(&s.as_bytes(),16);
        assert_eq!("ICE ICE BABY", String::from_utf8(t).unwrap());
    }

    #[test]
    #[should_panic(expected = "invalid padding")]
    fn test_c15b() {
        let s = "ICE ICE BABY\x05\x05\x05\x05";
        remove_pkcs7(&s.as_bytes(),16);
    }

    #[test]
    #[should_panic(expected = "invalid padding")]
    fn test_c15c() {
        let s = "ICE ICE BABY\x01\x02\x03\x04";
        remove_pkcs7(&s.as_bytes(),16);
    }

    #[test]
    fn test_c15d() {
        let s = "OH MY GOD, IT'S FULL OF STARS!!!";
        let t = remove_pkcs7(&pkcs7(&s.as_bytes(),16),16);
        assert_eq!(s,String::from_utf8(t).unwrap());
    }
}
