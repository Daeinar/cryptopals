use std::collections::HashMap;

pub fn analyse_frequency(x: &[u8]) -> u8 {
    let mut hmap = HashMap::new();
    for i in 0..x.len() { *hmap.entry(&x[i]).or_insert(0u32) += 1; }
    let mut max_v = 0u32;
    let mut key = 0u8;
    for (k,v) in hmap.iter() { if v > &max_v { max_v = *v; key = **k; } }
    key
}
