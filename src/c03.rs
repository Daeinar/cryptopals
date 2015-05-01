use std::collections::HashMap;

pub fn analyse_frequency(x: &[u8]) -> Vec<(u8,u32)> {
    let mut hmap = HashMap::new();
    for i in 0..x.len() { *hmap.entry(&x[i]).or_insert(0u32) += 1; } // count byte occurrences
    let mut y = hmap.iter().map(|x| (**x.0,*x.1)).collect::<Vec<(u8,u32)>>(); // re-write to vector for easier post-processing
    y.sort_by(|a, b| b.1.cmp(&a.1));
    y
}
