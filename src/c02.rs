#[cfg(test)]
mod test {
    use set01::{hex,unhex,xor};

    #[test]
    fn test_c02() {
        let x = "1c0111001f010100061a024b53535009181c";
        let y = "686974207468652062756c6c277320657965";
        let z = "746865206b696420646f6e277420706c6179";
        assert_eq!(z, hex(&xor(&unhex(x),&unhex(y))));
    }
}
