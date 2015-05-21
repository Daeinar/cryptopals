#[cfg(test)]
mod test {
    use set01::{read_file,find_ecb};

    #[test]
    fn test_c08() {
        let path = "src/c08.txt";
        let v = read_file(&path);
        assert_eq!(132, find_ecb(v,16));
    }
}
