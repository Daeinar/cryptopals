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
        if i % 16 == 15 {
            println!("");
        }
    }
    println!("");
}

pub fn store64(x: u64) -> Vec<u8> {
    (0..8).map(|i| (x >> 8*i) as u8).collect::<Vec<u8>>()
}

// little endian
pub fn load_be_u32(x: &[u8]) -> u32 {
    return ((x[0] as u32) <<  0) |
           ((x[1] as u32) <<  8) |
           ((x[2] as u32) << 16) |
           ((x[3] as u32) << 24);
}

pub fn store_le_u32(out: &mut[u8], x: u32) {
        out[0] = (x >>  0) as u8;
        out[1] = (x >>  8) as u8;
        out[2] = (x >> 16) as u8;
        out[3] = (x >> 24) as u8;
}

// big endian
pub fn load_be_u32(x: &[u8]) -> u32 {
    return ((x[0] as u32) << 24) |
           ((x[1] as u32) << 16) |
           ((x[2] as u32) <<  8) |
           ((x[3] as u32) <<  0);
}

pub fn store_be_u32(out: &mut[u8], x: u32) {
        out[0] = (x >> 24) as u8;
        out[1] = (x >> 16) as u8;
        out[2] = (x >>  8) as u8;
        out[3] = (x >>  0) as u8;
}

pub fn mult32(x: u32, y: u32) -> u32 {
    (Wrapping(x) * Wrapping(y)).0
}
pub fn add32(x: u32, y: u32) -> u32 {
    (Wrapping(x) + Wrapping(y)).0
}
