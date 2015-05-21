#[cfg(test)]
mod test {
    use set01::{encode_base64,unhex};

    #[test]
    fn test_c01() {
        let x = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let y = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(y, encode_base64(&unhex(x)));
    }
}
