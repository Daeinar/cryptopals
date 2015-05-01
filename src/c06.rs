pub fn hamming_distance(x: &[u8], y: &[u8]) -> u32 {
    assert_eq!(x.len(), y.len());
    (0..x.len()).map(|i| hamming_weight(x[i] ^ y[i])).fold(0, |mut a, b| {a += b; a})
}

pub fn hamming_weight(x: u8) -> u32 {
    let mut y = ((x as u32) & 0x55 ) + (((x as u32) >>  1) & 0x55 );
    y = (y & 0x33 ) + ((y >>  2) & 0x33 );
        (y & 0x0f ) + ((y >>  4) & 0x0f )
}
