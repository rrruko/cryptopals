use itertools::zip;

pub fn alph(c: u8) -> Option<u8> {
    if c >= 65 && c <= 90 {
        Some(c - 65)
    }
    else if c >= 97 && c <= 122 {
        Some(c - 97)
    }
    else {
        None
    }
}

pub fn histo(s: &[u8]) -> Vec<f32> {
    let mut v = vec![0.0; 26];
    let alpha_chars: Vec<u8> = s.iter().cloned().filter_map(alph).collect();
    for ix in &alpha_chars {
        v[*ix as usize] += 100.0 / alpha_chars.len() as f32;
    }
    v
}

pub fn diff(v1: &[f32], v2: &[f32]) -> Option<f32> {
    if v1.len() != v2.len() {
        None
    }
    else {
        Some(zip(v1, v2)
            .map(|(a, b)| (a - b).abs())
            .sum())
    }
}

pub fn score(s: &[u8]) -> f32 {
    let english_freq = [
        8.167,
        1.492,
        2.782,
        4.253,
        12.702,
        2.228,
        2.015,
        6.094,
        6.966,
        0.153,
        0.772,
        4.025,
        2.406,
        6.749,
        7.507,
        1.929,
        0.095,
        5.987,
        6.327,
        9.056,
        2.758,
        0.978,
        2.360,
        0.150,
        1.974,
        0.074
    ];
    diff(&histo(s), &english_freq).unwrap()
}
