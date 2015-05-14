pub fn pkcs7(x: &[u8], n: usize) -> Vec<u8> {
    assert!(n >= x.len());
    let mut y = x.to_vec();
    y.extend(vec![(n - x.len()) as u8; n - x.len()]);
    y
}
