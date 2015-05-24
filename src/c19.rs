
#[cfg(test)]
mod test {
    use set01::{decode_base64,xor};
    use set03::{CTROracle,filter_elements};

    #[test]
    fn test_c19() {
        let s: [&str; 40] = [
            "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
            "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
            "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
            "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
            "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
            "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
            "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
            "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
            "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
            "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
            "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
            "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
            "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
            "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
            "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
            "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
            "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
            "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
            "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
            "U2hlIHJvZGUgdG8gaGFycmllcnM/",
            "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
            "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
            "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
            "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
            "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
            "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
            "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
            "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
            "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
            "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
            "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
            "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
            "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
            "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
            "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
            "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="];

        let oracle = CTROracle::new();
        let nonce = [0x00; 8];
        let c = (0..s.len()).map(|i| oracle.encrypt(&nonce,&decode_base64(s[i]))).collect::<Vec<Vec<u8>>>();

        // find minimal length: we only recover the first min_l bytes
        let mut lengths = (0..c.len()).map(|i| c[i].len()).collect::<Vec<usize>>();
        lengths.sort_by(|a,b| a.cmp(&b));
        let min_l = lengths[0];

        // recovered plaintext: filled with _ to see missing letters
        let mut rp: Vec<Vec<u8>> = vec![ vec![0x5F; min_l]; 40 ];

        // specify filter
        let mut f0 = vec![];
          f0.push(b' ');
          f0.push(b',');
          f0.push(b'\'');
          f0.push(b'-');
          f0.push(b':');
          f0.extend(b'A'..b'Z');
          f0.extend(b'a'..b'z');

        // iterate over ciphertexts column-wise
        for i in 0..min_l {
            let mut candidates = vec![];
            for b in 0..256 { // guess bytes
                let d = (0..c.len()).map(|j| c[j][i]).collect::<Vec<u8>>();
                let v = filter_elements(&xor(&d,&vec![b as u8; 40]),&f0); // filter ascii elements
                if 40 == v.len() {
                    candidates.push(v.clone());
                }
            }
            //evaluate candidates (kinda ugly!)
            let x = match candidates.len() {
                0 => panic!("no candidates found"),
                1 => candidates.pop().unwrap(),
                _ => {
                    // specify filter
                    let mut f1 = vec![b' '];
                    f1.extend(b'A'..b'Z');
                    let mut y = candidates[0].clone();
                    for j in 0..candidates.len() {
                        let v = filter_elements(&candidates[j], &f1); // filter ascii elements
                        if 0 < v.len() {
                            y = candidates[j].clone();
                        }
                    }
                    y
                }
            };
            for k in 0..x.len() {
                rp[k][i] = x[k];
            }
        }
        // Only check some strings of the recovered plaintext. Recovering all of it would be quite tedious
        assert_eq!("A terrible beauty is",String::from_utf8(rp[15].clone()).unwrap());
        assert_eq!("This other man I had",String::from_utf8(rp[30].clone()).unwrap());
        assert_eq!("Transformed utterly:",String::from_utf8(rp[38].clone()).unwrap());
    }
}
