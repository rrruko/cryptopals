use stats::*;

use std::f32;
use itertools::zip;

pub fn fixed_xor(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    if a.len() != b.len() {
        None
    }
    else {
        Some(zip(a, b).map(|(a, b)| a ^ b).collect())
    }
}

pub fn repeating_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    bytes.iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect()
}

pub fn decrypt_single_byte_xor(bytes: &[u8]) -> (Vec<u8>, u8) {
    let mut best_score = (0, f32::INFINITY);
    for key in 1..127 {
        let ch = vec![key; bytes.len()];
        let x = fixed_xor(bytes, &ch).expect("ack");
        let s = score(&x);
        if best_score.1 > s {
            best_score = (key, s);
        }
    }

    let w = fixed_xor(bytes, &vec![best_score.0; bytes.len()]).unwrap();
    (w, best_score.0)
}

pub fn hamming(a: &[u8], b: &[u8]) -> Option<u64> {
    fixed_xor(a, b).map(|v|
        v.iter().map(|x| u64::from(x.count_ones())).sum()
    )
}
