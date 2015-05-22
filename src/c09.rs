#[cfg(test)]
mod test {
    use set02::pkcs7_pad;

    #[test]
    fn test_c09() {
        let x = "YELLOW SUBMARINE";
        let y = pkcs7_pad(&x.as_bytes(), 20);
        assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04", String::from_utf8(y).unwrap());
    }
}
