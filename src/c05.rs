pub fn repeating_key_xor(x: &[u8], k: &[u8]) -> Vec<u8> {
    let l = k.len();
    (0..x.len()).map(|i| x[i] ^ k[i%l]).collect::<Vec<u8>>()
}
