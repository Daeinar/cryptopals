extern crate cryptopals;

use cryptopals::c01::*;
use cryptopals::c02::*;
use cryptopals::c03::*;
use cryptopals::c04::*;
use cryptopals::c05::*;

#[test]
fn test_c01() {
    let x = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let y = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(y, base64(&unhex(x)));
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
    let x = analyse_file();
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
