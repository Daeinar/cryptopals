#[cfg(test)]
mod test {
    use set01::{read_file,frequency_analyse_list};

    #[test]
    fn test_c04() {
        let path = "src/c04.txt";
        let v = read_file(&path);
        let x = frequency_analyse_list(&v);
        let y = "nOWTHATTHEPARTYISJUMPING*";
        assert_eq!(x,y);
    }
}
