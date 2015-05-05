pub fn hamming_distance(x: &[u8], y: &[u8]) -> u32 {
    assert_eq!(x.len(), y.len());
    (0..x.len()).map(|i| hamming_weight(x[i] ^ y[i]) as u32).fold(0, |mut a, b| {a += b; a})
}

pub fn hamming_weight(x: u8) -> u8 {
    let mut y = (x & 0x55 ) + ((x >>  1) & 0x55 );
    y = (y & 0x33 ) + ((y >>  2) & 0x33 );
        (y & 0x0f ) + ((y >>  4) & 0x0f )
}

pub fn determine_keysizes(x: &[u8], n: usize) -> Vec<usize> {
    let mut d = (2..40).map(|i| (i,
            ((hamming_distance(&x[0*i..1*i],&x[1*i..2*i]) as f64 ) / (i as f64) +
             (hamming_distance(&x[2*i..3*i],&x[3*i..4*i]) as f64 ) / (i as f64) +
             (hamming_distance(&x[4*i..5*i],&x[5*i..6*i]) as f64 ) / (i as f64) +
             (hamming_distance(&x[6*i..7*i],&x[8*i..9*i]) as f64 ) / (i as f64)) / 4.0
            )).collect::<Vec<(usize,f64)>>();

    // do a simple insertion sort (note: sort_by() does not work for a f32/f64 vector)
    for i in 1..d.len() {
        let x = d[i];
        let mut j = i;
        while j > 0 && d[j-1].1 > x.1 {
           d[j] = d[j-1];
           j = j - 1;
        }
        d[j] = x
    }

    (0..n).map(|i| d[i].0).collect::<Vec<usize>>()
}

pub fn transpose(x: &[u8], n: usize) -> Vec<Vec<u8>> {
    let mut y = Vec::new();
    for _ in 0..n { y.push(Vec::new()); }
    for i in 0..x.len() {
        y[i%n].push(x[i]);
    }
    y
}
