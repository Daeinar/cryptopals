use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

use c01::*;
use c02::*;
use c03::*;

pub fn analyse_file() -> String {
    let file = match File::open("src/c04.txt") { Ok(file) => file, Err(..) => panic!("could not open file"), };
    let reader = BufReader::new(&file);
    let mut s = String::new();
    for line in reader.lines() {
        let x = match line { Ok(l) => l, Err(..) => panic!("cannot read line"), };
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

