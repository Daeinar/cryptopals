use c01::random_bytes;
use c09::pkcs7;
use c10::*;
use c15::remove_pkcs7;

pub struct CBCOracle { key: Vec<u8>, prefix: Vec<u8>, suffix: Vec<u8> }

impl CBCOracle {
    pub fn new() -> CBCOracle {
        CBCOracle { key: random_bytes(16), prefix: vec![], suffix: vec![]}
    }
    pub fn encrypt(&self, iv: &[u8], m: &[u8]) -> Vec<u8> {
        let n = vec![self.prefix.clone(), m.to_vec(), self.suffix.clone()].concat(); // encrypt prefix+msg+suffix
        aes128_cbc_encrypt(&self.key, &iv, &pkcs7(&n,16))
    }
    pub fn decrypt(&self, iv: &[u8], c: &[u8] ) -> Vec<u8> {
        remove_pkcs7(&aes128_cbc_decrypt(&self.key, &iv, &c),16)
    }
    pub fn set_prefix(&mut self, x: &[u8]) {
        self.prefix = x.to_vec();
    }
    pub fn set_suffix(&mut self, x: &[u8]) {
        self.suffix = x.to_vec();
    }
}

pub fn find_substring(s: &str, t: &str) -> bool {
    let x = s.to_string();
    match x.find(t) {
        None => false,
        _ => true
    }
}

#[cfg(test)]
mod test {
    use c16::*;

    #[test]
    fn test_c16a() {
        let oracle = CBCOracle::new();
        let s = "OOOH MY GOD, IT'S FULL OF STARS!";
        let iv = vec![0x00; 16];
        let c = oracle.encrypt(&iv, &s.as_bytes());
        let p = oracle.decrypt(&iv, &c);
        assert_eq!(s,String::from_utf8(p).unwrap());
    }

    #[test]
    fn test_c16b() {
        let s = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        assert_eq!(false,find_substring(s,";admin=true;"));
        let t = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true;";
        assert_eq!(true,find_substring(t,";admin=true;"));
    }
}
