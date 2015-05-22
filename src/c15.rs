#[cfg(test)]
mod test {
    use set02::{pkcs7_pad,pkcs7_unpad};

    #[test]
    fn test_c15a() {
        let s = "ICE ICE BABY\x04\x04\x04\x04";
        let t = pkcs7_unpad(&s.as_bytes(),16).unwrap();
        assert_eq!("ICE ICE BABY", String::from_utf8(t).unwrap());
    }

    #[test]
    fn test_c15b() {
        let s = "ICE ICE BABY\x05\x05\x05\x05";
        assert_eq!(None,pkcs7_unpad(&s.as_bytes(),16));
    }

    #[test]
    fn test_c15c() {
        let s = "ICE ICE BABY\x01\x02\x03\x04";
        assert_eq!(None,pkcs7_unpad(&s.as_bytes(),16));
    }

    #[test]
    fn test_c15d() {
        let s = "OH MY GOD, IT'S FULL OF STARS!!!";
        let t = pkcs7_unpad(&pkcs7_pad(&s.as_bytes(),16),16).unwrap();
        assert_eq!(s,String::from_utf8(t).unwrap());
    }
}
