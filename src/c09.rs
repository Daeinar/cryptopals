pub fn pkcs7(x: &[u8], n: usize) -> Vec<u8> {
    vec![x.to_vec(),vec![((n-x.len()%n)) as u8; ((n-x.len()%n))]].concat()
}


#[cfg(test)]
mod test {
    use c09::pkcs7;

    #[test]
    fn test_c09() {
        let x = "YELLOW SUBMARINE";
        let y = pkcs7(&x.as_bytes(), 20);
        assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04", String::from_utf8(y).unwrap());
    }
}
