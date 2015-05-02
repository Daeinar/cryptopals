use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

use c01::*;
use c02::*;
use c03::*;

pub fn read_file(path: &str) -> Vec<String> {
    let file = match File::open(path) { Ok(f) => f, Err(..) => panic!("could not open file"), };
    let reader = BufReader::new(&file);
    reader.lines().filter_map(|result| result.ok()).collect::<Vec<String>>()
}


pub fn frequency_analyse_list(lines: &Vec<String>) -> String {
    let mut s = String::new();
    for x in lines {
        let v = analyse_frequency(&unhex(&x));
        let k = v[0].0; // recover key
        let d = xor(&unhex(&x),&vec![k; x.len()/2]); // decrypt bytes
        let f = ascii(&d); // filter non-printable ASCII
        // assume that english text contains the highest number of printable ASCII
        if f.len() >= s.len() {
            s = String::from_utf8(f).unwrap();
        }
    }
    s
}

