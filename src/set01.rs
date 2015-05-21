extern crate rand;
extern crate openssl;

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::collections::HashMap;
use self::openssl::crypto::symm as cipher;
use self::rand::{thread_rng, Rng};

static CHARS: &'static[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// encode byte vector as base64 string
pub fn encode_base64(x: &[u8]) -> String {
    let mut s = Vec::with_capacity((x.len()/3)*4);
    for b in x.chunks(3) {
        let y = match b.len() {
            3 => ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | ((b[2] as u32) << 0),
            2 => ((b[0] as u32) << 10) | ((b[1] as u32) << 2),
            1 => ((b[0] as u32) <<  4),
            _ => panic!("invalid chunk size")
        };
        for i in 0..b.len()+1 { s.push(CHARS[((y >> 6*(b.len() - i)) & 0x3F) as usize]); }
        for _ in 0..3-b.len() { s.push(b'='); }
    }
    String::from_utf8(s).unwrap()
}

// decode base64 string to byte vector
pub fn decode_base64(x: &str) -> Vec<u8> {
    assert!(x.len()%4 == 0);
    fn convert(byte: u8) -> u8 {
        match byte {
            b'A'...b'Z' =>  0 + byte - b'A',
            b'a'...b'z' => 26 + byte - b'a',
            b'0'...b'9' => 52 + byte - b'0',
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid base64 character")
        }
    }
    fn is_padding(byte: u8) -> u8 {
        match byte {
            b'=' => 1,
            _ => 0
        }
    }
    x.as_bytes().chunks(4).map(|b| {
            let n = is_padding(b[2]) + is_padding(b[3]); // count number of padding bytes
            match n {
                0 => vec![(convert(b[0]) << 2) | (convert(b[1]) >> 4), (convert(b[1]) << 4) | (convert(b[2]) >> 2), (convert(b[2]) << 6) | convert(b[3])],
                1 => vec![(convert(b[0]) << 2) | (convert(b[1]) >> 4), (convert(b[1]) << 4) | (convert(b[2]) >> 2)],
                2 => vec![(convert(b[0]) << 2) | (convert(b[1]) >> 4)],
                _ => panic!("unknown number of padding bytes")
            }}).collect::<Vec<Vec<u8>>>().concat()
}

pub fn hex(x: &[u8]) -> String {
    (0..x.len()).map(|i| format!("{:02x}", x[i])).collect::<Vec<String>>().concat()
}

pub fn unhex(x: &str) -> Vec<u8> {
    assert!(x.len() % 2 == 0);
    fn convert(byte: u8) -> u8 {
        match byte {
        b'a'...b'f' => 10 + byte - b'a',
        b'A'...b'F' => 10 + byte - b'A',
        b'0'...b'9' => byte - b'0',
        _ => panic!("invalid hex character")
        }
    }
    x.as_bytes().chunks(2).map(|y| {(convert(y[0])<<4)|convert(y[1])} ).collect()
}

// filters non-printable ASCII bytes
pub fn ascii(x: &[u8]) -> Vec<u8> {
    x.iter().map(|y| y.clone()).filter(|&y| 31 < y && y < 127).collect::<Vec<u8>>()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut x = vec![0u8; n];
    rng.fill_bytes(&mut x);
    x
}

pub fn print_bytes(x: &[u8]) {
    for i in 0..x.len() {
        print!("{:02X} ", x[i]);
    }
    println!("");
}

pub fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    assert!(x.len() == y.len());
    (0..x.len()).map(|i| x[i] ^ y[i]).collect::<Vec<u8>>()
}

pub fn repeating_key_xor(x: &[u8], k: &[u8]) -> Vec<u8> {
    let l = k.len();
    (0..x.len()).map(|i| x[i] ^ k[i%l]).collect::<Vec<u8>>()
}

pub fn analyse_frequency(x: &[u8]) -> Vec<(u8,u32)> {
    let mut hmap = HashMap::new();
    for i in 0..x.len() { *hmap.entry(&x[i]).or_insert(0u32) += 1; } // count byte occurrences
    let mut y = hmap.iter().map(|x| (**x.0,*x.1)).collect::<Vec<(u8,u32)>>(); // re-write to vector for easier post-processing
    y.sort_by(|a, b| b.1.cmp(&a.1)); // sort the vector
    y
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

pub fn read_file(path: &str) -> Vec<String> {
    let file = match File::open(path) { Ok(f) => f, Err(..) => panic!("could not open file"), };
    let reader = BufReader::new(&file);
    reader.lines().filter_map(|result| result.ok()).collect::<Vec<String>>()
}

pub fn hamming_distance(x: &[u8], y: &[u8]) -> u32 {
    assert_eq!(x.len(), y.len());
    (0..x.len()).map(|i| hamming_weight(x[i] ^ y[i]) as u32).fold(0, |mut a, b| {a += b; a})
}

pub fn hamming_weight(x: u8) -> u8 {
    let mut y = (x & 0x55 ) + ((x >>  1) & 0x55 );
    y = (y & 0x33 ) + ((y >>  2) & 0x33 );
        (y & 0x0f ) + ((y >>  4) & 0x0f )
}

pub fn analyse_vigenere(ct: &[u8]) -> Vec<u8> {
    let keysizes = determine_vigenere_keysizes(&ct, 10); // get smallest 10 candidate key sizes
    let mut max_sum = 0;
    let mut key = Vec::new();
    for ks in keysizes {
        let blocks = transpose(&ct, ks);
        let mut sum = 0;
        let mut key_candidate = Vec::new();
        for i in 0..ks {
            let f = analyse_frequency(&blocks[i]);
            key_candidate.push(f[0].0); // assume key byte is the most frequent occuring byte
            let pt_block = xor(&blocks[i],&vec![key_candidate[i] as u8; blocks[i].len()]);
            let pt_ascii = ascii(&pt_block);
            sum += pt_ascii.len();
        }
        // evaluate
        if sum >= max_sum {
            max_sum = sum;
            key = key_candidate;
        }
    }
    key
}

fn determine_vigenere_keysizes(x: &[u8], n: usize) -> Vec<usize> {
    let mut d = (2..40).map(|i| (i,
            ((hamming_distance(&x[0*i..1*i],&x[1*i..2*i]) as f64 ) / (i as f64) +
             (hamming_distance(&x[2*i..3*i],&x[3*i..4*i]) as f64 ) / (i as f64) +
             (hamming_distance(&x[4*i..5*i],&x[5*i..6*i]) as f64 ) / (i as f64) +
             (hamming_distance(&x[6*i..7*i],&x[8*i..9*i]) as f64 ) / (i as f64)) / 4.0
            )).collect::<Vec<(usize,f64)>>();
    // do a simple insertion sort (note: sort_by() does not work for a f32/f64 vector)
    for i in 1..d.len() {
        let x = d[i];
        let mut j = i;
        while j > 0 && d[j-1].1 > x.1 {
           d[j] = d[j-1];
           j = j - 1;
        }
        d[j] = x
    }
    (0..n).map(|i| d[i].0).collect::<Vec<usize>>()
}

fn transpose(x: &[u8], n: usize) -> Vec<Vec<u8>> {
    let mut y = Vec::new();
    for _ in 0..n { y.push(Vec::new()); }
    for i in 0..x.len() {
        y[i%n].push(x[i]);
    }
    y
}

pub fn aes128_ecb_encrypt(k: &[u8], m: &[u8]) -> Vec<u8> {
    assert!(k.len() == 16 && m.len()%16 == 0);
    let aes = cipher::Crypter::new(cipher::Type::AES_128_ECB);
    aes.init(cipher::Mode::Encrypt, k, vec![]);
    aes.pad(false);
    m.chunks(16).map(|x| aes.update(x)).collect::<Vec<Vec<u8>>>().concat()
}

pub fn aes128_ecb_decrypt(k: &[u8], c: &[u8]) -> Vec<u8> {
    assert!(k.len() == 16 && c.len()%16 == 0);
    let aes = cipher::Crypter::new(cipher::Type::AES_128_ECB);
    aes.init(cipher::Mode::Decrypt, k, vec![]);
    aes.pad(false);
    c.chunks(16).map(|x| aes.update(x)).collect::<Vec<Vec<u8>>>().concat()
}

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
