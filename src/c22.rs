#[cfg(test)]
mod test {
    extern crate time;
    use set03::{MT19937};
    use utils::{random_u32};

    #[test]
    fn test_c22() {

        // seed Mersenne Twister with the current timestamp + random offset
        let mut mt = MT19937::new();
        let t = time::get_time().sec as u32;
        let o = random_u32() % 1000 + 40;
        let s = t+o;
        mt.seed(s);
        let x = mt.generate_random_u32();

        // seed another instance of MT with the current timestamp + max_offset
        let mut mtx = MT19937::new();
        let current_t = time::get_time().sec as u32;
        let max_o = 1500; // maximal assumed time offset since x was generated

        // recover the original seed
        let mut i = max_o + current_t;
        let mut r = 0;
        while i > 0 {
            mtx.seed(i);
            if x == mtx.generate_random_u32() {
                r = i;
                break;
            }
            i = i - 1;
        }
        assert_eq!(s,r);
    }
}
