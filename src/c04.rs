#[cfg(test)]
mod test {
    use set01::{frequency_analyse_list};
    use utils::{read_file};

    #[test]
    fn test_c04() {
        let path = "src/c04.txt";
        let v = read_file(&path);
        let x = frequency_analyse_list(&v);
        let y = "nOWTHATTHEPARTYISJUMPING*";
        assert_eq!(x,y);
    }
}
