pub fn repeating_key_xor(x: &[u8], k: &[u8]) -> Vec<u8> {
    let l = k.len();
    (0..x.len()).map(|i| x[i] ^ k[i%l]).collect::<Vec<u8>>()
}


#[cfg(test)]
mod test {
    use c01::hex;
    use c05::repeating_key_xor;

    #[test]
    fn test_c05() {
        let m = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let k = b"ICE";
        let c = hex(&repeating_key_xor(m, k));
        let d = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(c,d);
    }
}
