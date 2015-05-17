use std::collections::HashMap;

pub fn analyse_frequency(x: &[u8]) -> Vec<(u8,u32)> {
    let mut hmap = HashMap::new();
    for i in 0..x.len() { *hmap.entry(&x[i]).or_insert(0u32) += 1; } // count byte occurrences
    let mut y = hmap.iter().map(|x| (**x.0,*x.1)).collect::<Vec<(u8,u32)>>(); // re-write to vector for easier post-processing
    y.sort_by(|a, b| b.1.cmp(&a.1)); // sort the vector
    y
}


#[cfg(test)]
mod test {
    use c01::{unhex,ascii};
    use c02::xor;
    use c03::analyse_frequency;

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
