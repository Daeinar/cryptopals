use c01::random_bytes;
use c09::pkcs7;
use c10::*;
use c15::remove_pkcs7;

pub struct CBCOracle { key: Vec<u8> }

impl CBCOracle {
pub fn new() -> CBCOracle {
    CBCOracle { key: random_bytes(16) }
    }
    pub fn encrypt(&self, iv: &[u8], m: &[u8]) -> Vec<u8> {
        aes128_cbc_encrypt(&self.key, &iv, &pkcs7(&m,16))
    }
    pub fn decrypt(&self, iv: &[u8], c: &[u8] ) -> Vec<u8> {
        remove_pkcs7(&aes128_cbc_decrypt(&self.key, &iv, &c),16)
    }
}

pub fn create_message(prefix: &str, msg: &str, suffix: &str) -> String {
    vec![prefix,msg,suffix].concat().replace(";","\";\"").replace("=","\"=\"")
}

pub fn contains_string(s: &str, t: &str) -> bool {
    let x = s.to_string();
    match x.find(t) {
        None => false,
        _ => true
    }
}

#[cfg(test)]
mod test {
    use c01::ascii;
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
        let prefix = "comment1=cooking%20MCs;userdata=";
        let msg = "OOOH MY GOD, IT'S FULL OF STARS!";
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
        let s = "comment1\"=\"cooking%20MCs\";\"userdata\"=\"OOOH MY GOD, IT'S FULL OF STARS!\";\"comment2\"=\"%20like%20a%20pound%20of%20bacon";
        assert_eq!(s,create_message(prefix,msg,suffix));
    }

    #[test]
    fn test_c16c() {
        let s = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        assert_eq!(false,contains_string(s,";admin=true;"));
        let t = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true;";
        assert_eq!(true,contains_string(t,";admin=true;"));
    }

    #[test]
    fn test_c16d() {
        let prefix = "comment1=cooking%20MCs;userdata=";
        let msg = "FOO;admin=true";
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
        assert_eq!(false,contains_string(&create_message(prefix,msg,suffix),";admin=true;"));
    }

    #[test]
    fn test_c16e() {
        let oracle = CBCOracle::new();
        let prefix = "comment1=cooking%20MCs;userdata=";
        let msg = "FOOBAR!!;admin=true";
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
        let s = create_message(prefix,msg,suffix);
        let iv = vec![0x00;16];
        let mut c = oracle.encrypt(&iv, &s.as_bytes());
        c[32] ^= 0x19;
        c[38] ^= 0x1F;
        c[39] ^= 0x49;
        c[40] ^= 0x50;
        c[41] ^= 0x01;
        c[42] ^= 0x17;
        c[43] ^= 0x4E;
        let p = oracle.decrypt(&iv, &c);
        assert_eq!(true,contains_string(&String::from_utf8(ascii(&p)).unwrap(),";admin=true;"));
    }
}
