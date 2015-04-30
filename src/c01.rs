static CHARS: &'static[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// base64 encoding of a byte vector
pub fn base64(x: &[u8]) -> String {
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
    (0..x.len()).map(|i| format!("{:x}", x[i])).collect::<Vec<String>>().concat()
}

// filter non-printable ASCII bytes
pub fn ascii(x: &[u8]) -> Vec<u8> {
    x.iter().map(|y| y.clone()).filter(|&y| 31 < y && y < 127).collect::<Vec<u8>>()
}

