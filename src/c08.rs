use  c01::unhex;
use  c02::xor;

pub fn is_ecb_ciphertext(x: &[u8], b: usize) -> bool {
    for i in 0..x.len()/b {
        for j in i+1..x.len()/b {
            if &vec![0u8; b] == &xor(&x[b*i..b*(i+1)],&x[b*j..b*(j+1)]) {
                return true;
            }
        }
    }
    false
}

pub fn find_ecb(lines: Vec<String>, b: usize) -> i32 {
    for i in 0..lines.len() {
        let bytes = unhex(&lines[i]);
        if is_ecb_ciphertext(&bytes, b) {
            return i as i32;
        }
    }
    -1
}


#[cfg(test)]
mod test {
    use c04::read_file;
    use c08::find_ecb;

    #[test]
    fn test_c08() {
        let path = "src/c08.txt";
        let v = read_file(&path);
        assert_eq!(132, find_ecb(v,16));
    }
}
