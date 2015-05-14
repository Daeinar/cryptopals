extern crate cryptopals;

use cryptopals::c01::*;
use cryptopals::c02::*;
use cryptopals::c03::*;
use cryptopals::c04::*;
use cryptopals::c05::*;
use cryptopals::c06::*;
use cryptopals::c07::*;
use cryptopals::c08::*;
use cryptopals::c09::*;
use cryptopals::c10::*;

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
    let m = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let k = b"ICE";
    let c = hex(&repeating_key_xor(m, k));
    let d = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(c,d);
}

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

#[test]
fn test_c07() {
    let key = b"YELLOW SUBMARINE";
    let path = "src/c07.txt";
    let v = read_file(&path).concat();
    let ct = decode_base64(&v); // decode ciphertext
    assert_eq!(&ct, &aes128_ecb_encrypt(key, &aes128_ecb_decrypt(key, &ct)));
}

#[test]
fn test_c08() {
    let path = "src/c08.txt";
    let v = read_file(&path);
    assert_eq!(132, detect_aes_ecb(v));
}

#[test]
fn test_c09() {
    let x = "YELLOW SUBMARINE";
    let y = pkcs7(&x.as_bytes(), 20);
    assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04", String::from_utf8(y).unwrap());
}

#[test]
fn test_c10() {
    let key = b"YELLOW SUBMARINE";
    let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let path = "src/c10.txt";
    let v = read_file(&path).concat();
    let ct = decode_base64(&v);
    let pt = aes128_cbc_decrypt(key, iv, &ct);
    assert_eq!(ct, aes128_cbc_encrypt(key, iv, &pt));
}
