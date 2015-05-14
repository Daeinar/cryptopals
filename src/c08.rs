use  c01::*;
use  c02::*;

pub fn detect_aes_ecb(lines: Vec<String>) -> i32 {
    let mut line = -1;
    for i in 0..lines.len() {
        let bytes = unhex(&lines[i]);
        for j in 0..bytes.len()/16 {
            for k in j+1..bytes.len()/16 {
                if &vec![0u8; 16] == &xor(&bytes[16*j..16*(j+1)],&bytes[16*k..16*(k+1)]) {
                    line = i as i32;
                    break;
                }
            }
        }
    }
    line
}
