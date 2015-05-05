extern crate cryptopals;

use cryptopals::c01::*;
use cryptopals::c02::*;
use cryptopals::c03::*;
use cryptopals::c04::*;
use cryptopals::c05::*;
use cryptopals::c06::*;

#[test]
fn test_c01() {
    let x = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let y = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(y, encode_base64(&unhex(x)));
}

#[test]
fn test_c02() {
    let x = "1c0111001f010100061a024b53535009181c";
    let y = "686974207468652062756c6c277320657965";
    let z = "746865206b696420646f6e277420706c6179";
    assert_eq!(z, hex(&xor(&unhex(x),&unhex(y))));
}

#[test]
fn test_c03() {
    let x = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let v = analyse_frequency(&unhex(x));
    let k = v[0].0; // recover key
    let d = xor(&unhex(x),&vec![k; x.len()/2]); // decrypt bytes
    let f = ascii(&d); // filter non-printable ASCII
    assert_eq!(String::from_utf8(f).unwrap(), "cOOKINGmcSLIKEAPOUNDOFBACON");
}

#[test]
fn test_c04() {
    let path = "src/c04.txt";
    let v = read_file(&path);
    let x = frequency_analyse_list(&v);
    let y = "nOWTHATTHEPARTYISJUMPING*";
    assert_eq!(x,y);
}

#[test]
fn test_c05() {
    let m = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let k = "ICE";
    let c = hex(&repeating_key_xor(&m.as_bytes(), &k.as_bytes()));
    let d = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(c,d);
}

#[test]
fn test_c06() {

    // steps 1 & 2
    let x = "this is a test";
    let y = "wokka wokka!!!";
    assert_eq!(37, hamming_distance(&x.as_bytes(),&y.as_bytes()));

    // test base64 encoding and decoding
    assert_eq!(x,String::from_utf8(decode_base64(&encode_base64(&x.as_bytes()))).unwrap());

    // setps 3 & 4
    let path = "src/c06.txt";
    let v = read_file(&path).concat();
    let ct = decode_base64(&v); // decode ciphertext
    let keysizes = determine_keysizes(&ct, 10); // get smallest 10 candidate key sizes

    // steps 5 to 8
    let l = ct.len();
    let mut max_sum = 0;
    let mut key = Vec::new();
    let mut result = Vec::new();

    for ks in keysizes {
        let mut buffer = vec![0u8; l];
        let blocks = transpose(&ct, ks);
        let mut sum = 0;
        let mut key_candidate = Vec::new();
        for i in 0..ks {
            let f = analyse_frequency(&blocks[i]);
            key_candidate.push(f[0].0); // assume key byte is the highest occuring byte
            let pt_block = xor(&blocks[i],&vec![key_candidate[i] as u8; blocks[i].len()]);
            let pt_ascii = ascii(&pt_block);
            sum += pt_ascii.len();

            // sort back bytes
            for j in 0..pt_block.len() {
                buffer[ks*j+i] = pt_block[j];
            }
        }

        // evaluate
        if sum >= max_sum {
            max_sum = sum;
            key = key_candidate;
            result = buffer;
        }
    }

    // beautification of the plaintext
    for i in 0..result.len() {
        let byte = match result[i] {
            0x07 => 0x27,
            0x70 => 0x50,
            0x7F => 0x20,
            0x00...0x1F => 0x20,
            _ => result[i]
        };
        result[i] = byte;
    }

    assert_eq!(&key, &vec![0x74, 0x45, 0x52, 0x4D, 0x49, 0x4E,
                           0x41, 0x54, 0x4F, 0x52, 0x00, 0x78,
                           0x1A, 0x00, 0x62, 0x52, 0x49, 0x4E,
                           0x47, 0x00, 0x54, 0x48, 0x45, 0x00,
                           0x4E, 0x4F, 0x49, 0x53, 0x45]);

    //println!("plaintext: {}", String::from_utf8(result).unwrap())

}
