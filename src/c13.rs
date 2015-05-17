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
