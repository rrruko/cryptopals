use s_box::*;

use blockmode::*;
use na::{Matrix4};
use std::collections::HashMap;

type State = Matrix4<u8>;

#[derive(Debug, Copy, Clone)]
pub struct AES { block_size: usize }

pub const AES128: &AES = &AES { block_size: 16 };

impl BlockCipher for AES {
   fn encrypt(&self, chunk: &[u8], key: &[u8]) -> Vec<u8> {
        if self.block_size != 16 {
            unimplemented!()
        }
        let mut k = vec![0; self.block_size];
        k.copy_from_slice(key);
        from_matrix(aes128_chunk(to_matrix(chunk), &k))
    }
   fn decrypt(&self, chunk: &[u8], key: &[u8]) -> Vec<u8> {
        if self.block_size != 16 {
            unimplemented!()
        }
        let mut k = vec![0; self.block_size];
        k.copy_from_slice(key);
        from_matrix(aes128_decode_chunk(to_matrix(chunk), &k))
    }
   fn block_size(&self) -> usize {
        self.block_size
   }
}

pub fn to_matrix(bytes: &[u8]) -> State {
    Matrix4::from_fn(|r, c| bytes[4 * c + r])
}

pub fn from_matrix(state: State) -> Vec<u8> {
    state.data.as_slice().to_vec()
}

fn rotate(input: [u8; 4]) -> [u8; 4] {
    let mut output = input;
    for i in 0..4 {
        output[i] = input[(i + 1) % 4];
    }
    output
}

fn core(input: [u8; 4], i: usize) -> [u8; 4] {
    let mut output = input;
    output = rotate(output);
    for j in 0..4 {
        output[j] = S_BOX[output[j] as usize];
    }
    let rcon = |x| [
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97
    ][x];
    output[0] ^= rcon(i);
    output
}

fn aes128_key_schedule(key: &[u8], num_bytes: u8) -> Vec<u8> {
    let mut out = key.to_vec();
    let mut i = 1;
    let n = 16;
    while out.len() < num_bytes as usize {
        let mut next4 = [
            out[out.len() - 4],
            out[out.len() - 3],
            out[out.len() - 2],
            out[out.len() - 1]
        ];
        next4 = core(next4, i);
        i += 1;
        for _ in 0..4 {
            for i in 0..4 {
                next4[i] ^= out[out.len() - n + i];
            }
            out.extend(next4.iter());
        }
    }
    out
}

pub fn aes128_chunk(state: State, key: &[u8]) -> State {
    let rijndael_key = aes128_key_schedule(key, 176);
    let mut state = aes128_initial_round(state, to_matrix(&rijndael_key[0..16]));
    for i in 1..10 {
        let round_subkey = to_matrix(&rijndael_key[16 * i..16 * (i+1)]);
        state = aes128_round(state, round_subkey);
    }
    aes128_final_round(state, to_matrix(&rijndael_key[16 * 10..16 * 11]))
}

pub fn aes128_decode_chunk(state: State, key: &[u8]) -> State {
    let rijndael_key = aes128_key_schedule(key, 176);
    let mut state = aes128_final_inv(state, to_matrix(&rijndael_key[16 * 10 .. 16 * 11]));
    for i in 1..10 {
        let round_subkey = to_matrix(&rijndael_key[16 * (10 - i) .. 16 * (11 - i)]);
        state = aes128_round_inv(state, round_subkey);
    }
    aes128_initial_inv(state, to_matrix(&rijndael_key[0..16]))
}

fn aes128_initial_round(state: State, subkey: Matrix4<u8>) -> State {
    add_round_key(state, subkey)
}

fn aes128_initial_inv(state: State, subkey: Matrix4<u8>) -> State {
    inv_add_round_key(state, subkey)
}

fn aes128_round(state: State, subkey: Matrix4<u8>) -> State {
    let mut state = sub_bytes(state);
    state = shift_rows(state);
    state = mix_columns(state);

    add_round_key(state, subkey)
}

fn aes128_round_inv(state: State, subkey: Matrix4<u8>) -> State {
    let mut state = inv_add_round_key(state, subkey);
    state = inv_mix_columns(state);
    state = inv_shift_rows(state);

    inv_sub_bytes(state)
}

fn aes128_final_round(state: State, subkey: Matrix4<u8>) -> State {
    let mut state = sub_bytes(state);
    state = shift_rows(state);

    add_round_key(state, subkey)
}

fn aes128_final_inv(state: State, subkey: Matrix4<u8>) -> State {
    let mut state = inv_add_round_key(state, subkey);
    state = inv_shift_rows(state);

    inv_sub_bytes(state)

}

/* Operations */

fn sub_bytes(state: State) -> State {
    state.map(|e| S_BOX[e as usize])
}

fn inv_sub_bytes(state: State) -> State {
    state.map(|e| INV_S_BOX[e as usize])
}

fn shift_rows(state: State) -> State {
    Matrix4::from_fn(|r, c| unsafe { *state.get_unchecked(r, (c + r) % 4) })
}

fn inv_shift_rows(state: State) -> State {
    Matrix4::from_fn(|r, c| unsafe { *state.get_unchecked(r, c.wrapping_sub(r) % 4) })
}

fn gmul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p = 0;
    let mut hi_bit_set;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        hi_bit_set = a & 0x80;
        a <<= 1;
        if hi_bit_set != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

fn mix_columns(state: State) -> State {
    unsafe {
        let mat = Matrix4::new(
            2, 3, 1, 1,
            1, 2, 3, 1,
            1, 1, 2, 3,
            3, 1, 1, 2);
        let get = |x, y| *state.get_unchecked(x, y);
        let gmt = |x, y| *mat.get_unchecked(x, y);
        Matrix4::from_fn(|r, c|
            gmul(gmt(r, 0), get(0, c)) ^
            gmul(gmt(r, 1), get(1, c)) ^
            gmul(gmt(r, 2), get(2, c)) ^
            gmul(gmt(r, 3), get(3, c))
        )
    }
}

fn inv_mix_columns(state: State) -> State {
    unsafe {
        let mat = Matrix4::new(
            14, 11, 13,  9,
             9, 14, 11, 13,
            13,  9, 14, 11,
            11, 13,  9, 14);
        let get = |x, y| *state.get_unchecked(x, y);
        let gmt = |x, y| *mat.get_unchecked(x, y);
        Matrix4::from_fn(|r, c|
            gmul(gmt(r, 0), get(0, c)) ^
            gmul(gmt(r, 1), get(1, c)) ^
            gmul(gmt(r, 2), get(2, c)) ^
            gmul(gmt(r, 3), get(3, c))
        )
    }
}

fn add_round_key(state: State, subkey: Matrix4<u8>) -> State {
    unsafe {
        Matrix4::from_fn(|r, c|
            *state.get_unchecked(r, c) ^
            *subkey.get_unchecked(r, c)
        )
    }
}

fn inv_add_round_key(state: State, subkey: Matrix4<u8>) -> State {
    add_round_key(state, subkey)
}

// The higher the value of a key in the hashmap, the more that chunk appears
// duplicated in the ciphertext, the more likely the use of ECB.
pub fn detect_ecb(b: &[u8]) -> HashMap<&[u8], u32> {
    let mut seen = HashMap::new();
    for chunk in b.chunks(16) {
        seen.entry(chunk)
            .and_modify(|n| { *n += 1 })
            .or_insert(1);
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_matrix() {
        let m = to_matrix(&[
             1,  2,  3,  4,
             5,  6,  7,  8,
             9, 10, 11, 12,
            13, 14, 15, 16]);
        let res = Matrix4::new(
            1,  5,  9, 13,
            2,  6, 10, 14,
            3,  7, 11, 15,
            4,  8, 12, 16);
        assert_eq!(m, res);
    }

    #[test]
    fn test_rotate() {
        assert_eq!(rotate([4, 8, 15, 16]), [8, 15, 16, 4]);
    }

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
        // Yanked from Wikipedia
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

    #[test]
    fn test_inv_mix_columns() {
        let state = Matrix4::new(
            0xdb, 0x13, 0x53, 0x45,
            0xf2, 0x0a, 0x22, 0x5c,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6).transpose();
        assert_eq!(inv_mix_columns(mix_columns(state)), state);
    }

    #[test]
    fn test_key_schedule() {
        let key = &[0; 16];
        let expanded = aes128_key_schedule(key, 176);
        assert_eq!(expanded[0], 0x0);
        assert_eq!(expanded[16], 0x62);
        assert_eq!(expanded[32], 0x9b);
        assert_eq!(expanded[175], 0x8e);
    }

    #[test]
    fn test_aes128_round_inv() {
        let state = Matrix4::from_fn(|r, c| (r * 4 + c) as u8);
        let subkey = Matrix4::new(
            0xdb, 0x13, 0x53, 0x45,
            0xf2, 0x0a, 0x22, 0x5c,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6);
        assert_eq!(aes128_round_inv(aes128_round(state, subkey), subkey), state);
    }

    #[test]
    fn test_aes() {
        // Yanked from AES spec
        // (http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee
        ];
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        ];
        let enc = ecb_encrypt(AES128, &plaintext, &key);
        assert_eq!(ecb_decrypt(AES128, &enc, &key).unwrap(), plaintext);

        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ];
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        ];
        let enc = ecb_encrypt(AES128, &plaintext, &key);
        assert_eq!(ecb_decrypt(AES128, &enc, &key).unwrap(), plaintext);
    }

}
