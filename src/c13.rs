extern crate rand;

use std::collections::HashMap;

pub fn parse(s: &str) -> HashMap<&str,&str> {
    let v: Vec<&str> = s.split('&').collect();
    let mut hmap = HashMap::new();
    for x in v {
        let t: Vec<&str> = x.split('=').collect();
        hmap.insert(t[0], t[1]);
    }
    hmap
}

pub fn profile_for(s :&str) -> String {
    vec!["email=",&s.replace("=","").replace("&",""),"&uid=10&role=user"].concat()
}


#[cfg(test)]
mod test {
    use c12::*;
    use c13::*;

    #[test]
    fn test_c13() {
        let oracle = ECBOracle::new();
        let profile = profile_for("foo@bar.deadmin              "); // create profile: note the padding with spaces
        let c = oracle.encrypt(&profile.as_bytes()); // encrypt profile
        // rearrange ciphertext blocks
        let mod_c = vec![c[0..16].to_vec(),c[32..48].to_vec(),c[16..32].to_vec()].concat();
        // decrypt plaintext
        let p = String::from_utf8(oracle.decrypt(&mod_c)).unwrap();
        // parse profile
        let hmap = parse(&p);
        assert_eq!(hmap["role"].replace(" ",""),"admin");
    }
}
