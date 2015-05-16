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
    let email = s.replace("=","").replace("&","");
    let mut profile = String::new();
    profile.push_str("email=");
    profile.push_str(&email);
    profile.push_str("&uid=10&role=user");
    profile
}
