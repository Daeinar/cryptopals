pub fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    assert!(x.len() == y.len());
    (0..x.len()).map(|i| x[i] ^ y[i]).collect::<Vec<u8>>()
}
