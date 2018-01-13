use na::{Matrix4};
use s_box::*;

type State = Matrix4<u8>;

fn aes(keysize: u16) {

}

fn sub_bytes(state: State) -> State {
    state.map(|e| S_BOX[e as usize])
}

fn shift_rows(state: State) -> State {
    Matrix4::from_fn(|r, c| unsafe { *state.get_unchecked(r, (c + r) % 4) })
}

fn gmul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p = 0;
    let mut hi_bit_set = 0;
    for counter in (0..8) {
        if (b & 1) != 0 {
            p ^= a;
        }
        hi_bit_set = a & 0x80;
        a = a << 1;
        if hi_bit_set != 0 {
            a ^= 0x1b;
        }
        b = b >> 1;
    }
    return p;
}

fn mix_columns(state: State) -> State {
    unsafe {
        let get = |x, y| *state.get_unchecked(x, y);
        Matrix4::from_fn(|r, c|
            match r {
                0 => gmul(2, get(0, c)) ^ gmul(3, get(1, c)) ^ get(2, c) ^ get(3, c),
                1 => get(0, c) ^ gmul(2, get(1, c)) ^ gmul(3, get(2, c)) ^ get(3, c),
                2 => get(0, c) ^ get(1, c) ^ gmul(2, get(2, c)) ^ gmul(3, get(3, c)),
                3 => gmul(3, get(0, c)) ^ get(1, c) ^ get(2, c) ^ gmul(2, get(3, c)),
                _ => unreachable!()
            }
        )
    }
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
        assert_eq!(shift_rows(state), result);
    }

    #[test]
    fn test_mix_columns() {
        let state = Matrix4::new(
            0xdb, 0x13, 0x53, 0x45,
            0xf2, 0x0a, 0x22, 0x5c,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6).transpose();
        let result = Matrix4::new(
            0x8e, 0x4d, 0xa1, 0xbc,
            0x9f, 0xdc, 0x58, 0x9d,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6).transpose();
        assert_eq!(mix_columns(state), result);
    }
}
