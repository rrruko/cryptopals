use na::{Matrix4};
use s_box::*;

type State = Matrix4<u8>;

fn aes(keysize: u16) {
}

fn sub_bytes(state: State) -> State {
    state.map(|e| S_BOX[e as usize])
}

// ??? I have no idea how to write this better
unsafe fn shift_rows(state: State) -> State {
    Matrix4::from_fn(|r, c| *state.get_unchecked(r, (c + r) % 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sub_bytes() {
        let state = Matrix4::new(
             1,  2,  3,  4,
             5,  6,  7,  8,
             9, 10, 11, 12,
            13, 14, 15, 16);
        let result = Matrix4::new(
            124, 119, 123, 242,
            107, 111, 197,  48,
              1, 103,  43, 254,
            215, 171, 118, 202);
        assert_eq!(sub_bytes(state), result);
    }

    #[test]
    fn test_shift_rows() {
        let state = Matrix4::new(
             1,  2,  3,  4,
             5,  6,  7,  8,
             9, 10, 11, 12,
            13, 14, 15, 16);
        let result = Matrix4::new(
             1,  2,  3,  4,
             6,  7,  8,  5,
            11, 12,  9, 10,
            16, 13, 14, 15);
        unsafe { assert_eq!(shift_rows(state), result); }
    }
}
