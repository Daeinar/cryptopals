use std::collections::HashMap;

pub fn analyse_frequency(x: &[u8]) -> u8 {
    let mut count = HashMap::new();
    for i in 0..x.len() {
        *count.entry(&x[i]).or_insert(0u32) += 1;
    }
    let mut max_v = 0u32;
    let mut max_k = 0u8;
    for (k,v) in count.iter() { if v > &max_v { max_v = *v; max_k = **k; } }
    max_k
}


