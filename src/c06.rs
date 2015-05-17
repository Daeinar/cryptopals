use c01::*;
use c02::*;
use c03::*;

pub fn hamming_distance(x: &[u8], y: &[u8]) -> u32 {
    assert_eq!(x.len(), y.len());
    (0..x.len()).map(|i| hamming_weight(x[i] ^ y[i]) as u32).fold(0, |mut a, b| {a += b; a})
}

pub fn hamming_weight(x: u8) -> u8 {
    let mut y = (x & 0x55 ) + ((x >>  1) & 0x55 );
    y = (y & 0x33 ) + ((y >>  2) & 0x33 );
        (y & 0x0f ) + ((y >>  4) & 0x0f )
}

fn determine_keysizes(x: &[u8], n: usize) -> Vec<usize> {
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

pub fn analyse_vigenere(ct: &[u8]) -> Vec<u8> {
    let keysizes = determine_keysizes(&ct, 10); // get smallest 10 candidate key sizes
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


#[cfg(test)]
mod test {
    use c01::{encode_base64,decode_base64};
    use c04::read_file;
    use c06::*;

    #[test]
    fn test_c06() {
        let x = "this is a test";
        let y = "wokka wokka!!!";
        assert_eq!(37, hamming_distance(&x.as_bytes(),&y.as_bytes()));
        assert_eq!(x,String::from_utf8(decode_base64(&encode_base64(&x.as_bytes()))).unwrap()); // test base64 encoding and decoding
        let path = "src/c06.txt";
        let v = read_file(&path).concat();
        let ct = decode_base64(&v); // decode ciphertext
        let key = analyse_vigenere(&ct); // steps 3 to 8
        assert_eq!(&key, &vec![0x74, 0x45, 0x52, 0x4D, 0x49, 0x4E,
                               0x41, 0x54, 0x4F, 0x52, 0x00, 0x78,
                               0x1A, 0x00, 0x62, 0x52, 0x49, 0x4E,
                               0x47, 0x00, 0x54, 0x48, 0x45, 0x00,
                               0x4E, 0x4F, 0x49, 0x53, 0x45]);
    }
}
