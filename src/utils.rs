extern crate rand;

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::num::Wrapping;
use self::rand::{thread_rng, Rng};

pub fn read_file(path: &str) -> Vec<String> {
    let file = match File::open(path) { Ok(f) => f, Err(..) => panic!("could not open file"), };
    let reader = BufReader::new(&file);
    reader.lines().filter_map(|result| result.ok()).collect::<Vec<String>>()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut x = vec![0u8; n];
    rng.fill_bytes(&mut x);
    x
}

pub fn random_u32() -> u32 {
    let mut rng = thread_rng();
    rng.gen::<u32>()
}

pub fn print_bytes(x: &[u8]) {
    for i in 0..x.len() {
        print!("{:02X} ", x[i]);
    }
    println!("");
}

pub fn store64(x: u64) -> Vec<u8> {
    (0..8).map(|i| (x >> 8*i) as u8).collect::<Vec<u8>>()
}

pub fn mult32(x: u32, y: u32) -> u32 {
    (Wrapping(x) * Wrapping(y)).0
}
pub fn add32(x: u32, y: u32) -> u32 {
    (Wrapping(x) + Wrapping(y)).0
}
