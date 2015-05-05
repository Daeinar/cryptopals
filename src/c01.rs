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


pub fn hex(x: &[u8]) -> String {
    (0..x.len()).map(|i| format!("{:02x}", x[i])).collect::<Vec<String>>().concat()
}

// filters non-printable ASCII bytes
pub fn ascii(x: &[u8]) -> Vec<u8> {
    x.iter().map(|y| y.clone()).filter(|&y| 31 < y && y < 127).collect::<Vec<u8>>()
}

pub fn print_bytes(x: &[u8]) {
    for i in 0..x.len() {
        print!("{:02X} ", x[i]);
    }
    println!("");
}
