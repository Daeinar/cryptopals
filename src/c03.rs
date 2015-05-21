#[cfg(test)]
mod test {
    use set01::{unhex,ascii,xor,analyse_frequency};

    #[test]
    fn test_c03() {
        let x = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let v = analyse_frequency(&unhex(x));
        let k = v[0].0; // recover key
        let d = xor(&unhex(x),&vec![k; x.len()/2]); // decrypt bytes
        let f = ascii(&d); // filter non-printable ASCII
        assert_eq!(String::from_utf8(f).unwrap(), "cOOKINGmcSLIKEAPOUNDOFBACON");
    }
}
