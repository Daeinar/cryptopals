pub fn pkcs7(x: &[u8], n: usize) -> Vec<u8> {
    let mut y = x.to_vec();
    y.extend(vec![((n-x.len()%n)%n) as u8; ((n-x.len()%n)%n)]);
    y
}
