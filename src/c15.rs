pub fn reverse_pkcs7(x: &[u8], n: usize) -> Vec<u8> {
    assert!(x.len()%n == 0);
    let l = x[x.len()-1] as usize;
    for i in 0..l {
        if l != x[x.len()-1-i] as usize {
            panic!("invalid padding");
        }
    }
    x[0..(x.len()-l as usize)].to_vec()
}


#[cfg(test)]
mod test {
    use c15::reverse_pkcs7;

    #[test]
    fn test_c15a() {

        let s = "ICE ICE BABY\x04\x04\x04\x04";
        let t = reverse_pkcs7(&s.as_bytes(),16);
        assert_eq!("ICE ICE BABY", String::from_utf8(t).unwrap());
    }

    #[test]
    #[should_panic(expected = "invalid padding")]
    fn test_c15b() {
        let s = "ICE ICE BABY\x01\x02\x03\x04";
        let t = reverse_pkcs7(&s.as_bytes(),16);
    }

}
