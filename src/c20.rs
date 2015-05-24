#[cfg(test)]
mod test {
    use set01::{decode_base64};
    use set03::{CTROracle,attack_ctr};
    use utils::{read_file};

    #[test]
    fn test_c20() {

        let path = "c20.txt";
        let lines = read_file(&path);
        let oracle = CTROracle::new();
        let nonce = [0x00; 8];

        let c = lines.iter().map(|x| oracle.encrypt(&nonce,&decode_base64(x))).collect::<Vec<Vec<u8>>>();

        let mut filter_a = vec![b' ', b',', b'\'', b'.', b'\"', b'/', b'-', b'!', b'?', b':'];
        filter_a.extend(b'A'..(b'Z'+1));
        filter_a.extend(b'a'..(b'z'+1));
        filter_a.extend(b'0'..(b'9'+1));

        let filter_b = vec![b' '];

        let p = attack_ctr(&c, &filter_a, &filter_b);

        assert_eq!("I'm rated \"R\"...this is a warning, ya better void / P",String::from_utf8(p[0].clone()).unwrap());
        assert_eq!("Kara Lewis is our agent, word up / Zakia and 4th and ",String::from_utf8(p[38].clone()).unwrap());
        assert_eq!("A pen and a paper, a stereo, a tape of / Me and Eric ",String::from_utf8(p[50].clone()).unwrap());
    }
}
