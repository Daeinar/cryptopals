use std::collections::HashMap;

pub fn analyse_frequency(x: &[u8]) -> Vec<(u8,u32)> {
    let mut hmap = HashMap::new();
    for i in 0..x.len() { *hmap.entry(&x[i]).or_insert(0u32) += 1; }
    let mut y = Vec::<(u8,u32)>::new();
    for (k,v) in hmap.iter() { y.push((**k,*v)) }
    y.sort_by(|a, b| b.1.cmp(&a.1));
    y
}
