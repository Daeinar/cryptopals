use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

use c01::*;
use c02::*;
use c03::*;

pub fn test_io() {
    let file = match File::open("src/4.txt") { Ok(file) => file, Err(..)  => panic!("room"), };
    let reader = BufReader::new(&file);
    let mut i = 0;
    for line in reader.lines() {
        let x = match line { Ok(l)   => l, Err(..) => panic!("line"), };
        let v = analyse_frequency(&unhex(&x));
        let k = v[0].0; // recover key
        let d = xor(&unhex(&x),&vec![k; x.len()/2]); // decrypted bytes
        let f = ascii(&d); // filter non-printable ASCII
        println!("{:03}: {}",i,String::from_utf8(f).unwrap());
        i += 1;
    }
}

