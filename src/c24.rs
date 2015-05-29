#[cfg(test)]
mod test {
    extern crate time;
    use set01::{xor};
    use set03::{MT19937,MT19937Oracle,is_ticket};

    #[test]
    fn test_c24a() {
        let mut oracle = MT19937Oracle::new();
        oracle.init();
        let m = b"AAAAAAAAAAAAAA";
        let c = oracle.encrypt(m);

        let v = vec![ vec![0x00; c.len() - m.len()], m.to_vec()].concat();
        let mut mt = MT19937::new();
        let mut key = 0;
        let mut s = vec![0x00; v.len()];
        for i in 0..65536 {
            mt.seed(i);
            mt.fill_bytes(&mut s);
            let d = xor(&v,&s);
            if c[(c.len() - m.len())..] == d[(d.len() - m.len())..] {
                key = i as u16;
                break;
            }
        }
        assert!(oracle.verify_key(key));
    }

    #[test]
    fn test_c24b() {
        let mut mt = MT19937::new();
        mt.seed(time::get_time().sec as u32);
        let mut ticket = [0x00; 16];
        mt.fill_bytes(&mut ticket);
        assert!(is_ticket(&ticket));
    }
}
