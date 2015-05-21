#[cfg(test)]
mod test {
    use set02::{ECBOracle,get_profile,parse_profile};

    #[test]
    fn test_c13() {
        let oracle = ECBOracle::new();
        let profile = get_profile("foo@bar.deadmin              "); // create profile: note the padding with spaces
        let c = oracle.encrypt(&profile.as_bytes()); // encrypt profile
        // rearrange ciphertext blocks
        let mod_c = vec![c[0..16].to_vec(),c[32..48].to_vec(),c[16..32].to_vec()].concat();
        // decrypt plaintext
        let p = String::from_utf8(oracle.decrypt(&mod_c)).unwrap();
        // parse profile
        let hmap = parse_profile(&p);
        assert_eq!(hmap["role"].replace(" ",""),"admin");
    }
}
