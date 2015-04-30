extern crate cryptopals;

use cryptopals::c01::base64;
use cryptopals::c01::unhex;
use cryptopals::c01::hex;

#[test]
fn test_c01() {
    let x = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let y = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(y, base64(&unhex(x)));
}

use cryptopals::c02::xor;

#[test]
fn test_c02() {
    let x = "1c0111001f010100061a024b53535009181c";
    let y = "686974207468652062756c6c277320657965";
    let z = "746865206b696420646f6e277420706c6179";
    assert_eq!(z, hex(&xor(&unhex(x),&unhex(y))));
}

use cryptopals::c01::ascii;
use cryptopals::c03::analyse_frequency;

#[test]
fn test_c03() {
    let x = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let k = analyse_frequency(&unhex(x)); // recover key
    let d = xor(&unhex(x),&vec![k; x.len()/2]); // decrypted bytes
    let f = ascii(&d); // filter non-printable ASCII
    assert_eq!(String::from_utf8(f).unwrap(), "cOOKINGmcSLIKEAPOUNDOFBACON");
}
