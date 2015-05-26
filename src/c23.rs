#[cfg(test)]
mod test {
    extern crate time;
    use set03::{MT19937,untemper};

    #[test]
    fn test_c23() {
        let mut mt = MT19937::new();
        mt.seed(time::get_time().sec as u32);
        let mut x = [0; 624];
        for i in 0..624 {
            x[i] = untemper(mt.generate_random_u32());
        }
        let mut mtx = MT19937::new();
        mtx.set_state(&x);
        for _ in 0..1248 {
            assert_eq!(mt.generate_random_u32(),mtx.generate_random_u32());
        }
    }
}
