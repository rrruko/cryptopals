pub struct MersenneTwister {
    pointer: usize,
    state: [u32; 624]
}

impl MersenneTwister {
    pub fn new(seed: u32) -> Self {
        let mut state = [0; 624];
        state[0] = seed;

        let f: u32 = 1812433253;

        for i in 1..state.len() {
            let prev = state[i - 1];
            let r = (prev ^ (prev >> 30));
            state[i] = f.overflowing_mul(r).0 + i as u32;
        }

        MersenneTwister { pointer: 624, state: state }
    }

    fn step(&mut self) {
        let state = &mut self.state;
        let l = state.len();
        let lower_mask = 0x7fffffff;
        let upper_mask = 0x80000000;

        for i in 0..=226 {
            let temp = (state[i] & upper_mask) | (state[i + 1] & lower_mask);
            state[i] =
                (temp >> 1) ^
                (if temp % 2 == 0 { 0 } else { 0x9908b0df }) ^
                state[i + 397];
        }
        for i in 227..=622 {
            let temp = (state[i] & upper_mask) | (state[i + 1] & lower_mask);
            state[i] =
                (temp >> 1) ^
                (if temp % 2 == 0 { 0 } else { 0x9908b0df }) ^
                state[i - 227];
        }
        let temp = (state[623] & upper_mask) | (state[0] & lower_mask);
        state[623] =
            (temp >> 1) ^
            (if temp % 2 == 0 { 0 } else { 0x9908b0df }) ^
            state[396];
    }

    fn get(&self) -> u32 {
        let mut temp = self.state[self.pointer];
        temp ^= temp >> 11;
        temp ^= (temp << 7)  & 0x9d2c5680;
        temp ^= (temp << 15) & 0xefc60000;
        temp ^= temp >> 18;
        temp
    }

    fn undo_right_18(t: u32) -> u32 {
        let mut t = t;
        t ^= (t & 0b11111111111111111100000000000000) >> 18;
        t ^= (t & 0b00000000000000000011111111111111) >> 18;
        t
    }

    fn undo_right_11(t: u32) -> u32 {
        let mut t = t;
        t ^= (t & 0b11111111111000000000000000000000) >> 11;
        t ^= (t & 0b00000000000111111111110000000000) >> 11;
        t ^= (t & 0b00000000000000000000001111111111) >> 11;
        t
    }

    /*
    pub fn untemper(n: u32) -> u32 {
        let mut n = n;
        n = undo_right_18(n);
        n = undo_left_15(n);
        n = undo_left_7(n);
        n = undo_right_11(n);
        n
    }
    */

    pub fn next(&mut self) -> u32 {
        if self.pointer >= self.state.len() {
            self.step();
            self.pointer = 0;
        }
        let result = self.get();
        self.pointer += 1;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_seed_0() {
        let mut mt = MersenneTwister::new(0);
        let first_out = mt.next();
        assert_eq!(first_out, 2357136044);
        for _ in 1..999 {
            mt.next();
        }
        let thousandth_out = mt.next();
        assert_eq!(thousandth_out, 3043451800);
    }
}
