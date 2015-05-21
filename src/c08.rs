#[cfg(test)]
mod test {
    use set01::{find_ecb};
    use utils::{read_file};

    #[test]
    fn test_c08() {
        let path = "src/c08.txt";
        let v = read_file(&path);
        assert_eq!(132, find_ecb(v,16));
    }
}
