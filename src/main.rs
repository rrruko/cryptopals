#![feature(slice_patterns)]

extern crate cryptopals;
extern crate itertools;

use std::cmp::Ordering;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::option::Option;
use std::str;
use std::vec::Vec;
use itertools::Itertools;
use itertools::zip;

fn main() {
    test();
}

fn test() {
    test_base64();
    _1();
    _2();
    _3();
    _4();
    _5();
    _6();
}

fn test_base64() {
    identity(b"Ringo mogire beam");
    identity(b"Ringo mogire beam!");
    identity(b"Ringo mogire beam!!");
}

fn identity(v: &[u8]) {
    let enc: &[u8] = &base64_encode(v);
    let dec: &[u8] = &base64_decode(enc);
    assert_eq!(v, dec);
}

fn _1() {
    let mut file = File::open("data/1.txt").expect("no 1.txt");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Couldn't read to string");
    let contents = contents.trim();
    let bytes = base16_decode(contents);
    let base64enc = base64_encode(bytes.as_slice());
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        str::from_utf8(&base64enc).unwrap());
}

fn _2() {
    let xor1 = "1c0111001f010100061a024b53535009181c";
    let xor2 = "686974207468652062756c6c277320657965";
    let res  = "746865206b696420646f6e277420706c6179";

    let ans = fixed_xor(
        &base16_decode(xor1),
        &base16_decode(xor2)
    ).unwrap();
    assert_eq!(base16_encode(&ans), res);
}

fn _3() {
    let code = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let bytes = base16_decode(code);
    let ans = decrypt_single_byte_xor(&bytes).unwrap().0;
    assert_eq!("Cooking MC's like a pound of bacon", ans);
}

fn _4() {
    let file = File::open("data/4.txt").expect("no 4.txt");
    let buf_reader = BufReader::new(file);
    let l = buf_reader.lines();
    for line in l {
        let bytes = base16_decode(&line.expect("no line"));
        if let Ok(res) = decrypt_single_byte_xor(&bytes) {
            println!("{}", res.0);
        }
    }
}

fn _5() {
    let raw = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";

    let enc = repeating_xor(raw, key);
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(enc, base16_decode(expected));

    let dec = repeating_xor(&enc, key);
    assert_eq!(raw[..], dec[..]);
}

fn _6() {
    let test = hamming(b"this is a test",
                       b"wokka wokka!!!");
    assert_eq!(test.unwrap(), 37);
    let mut file = File::open("data/6.txt").expect("no 6.txt");
    let mut base64_bytes = Vec::new();
    file.read_to_end(&mut base64_bytes).unwrap();
    base64_bytes = base64_bytes.into_iter().filter(|&x| x > 32).collect();
    println!("{:?}", &base64_bytes);
    let bytes = base64_decode(&base64_bytes);
    println!("{:?}", bytes);
    let mut key_scores = Vec::<(usize, f64)>::new();
    for keysize in 2..40 {
        let f = &bytes[0..keysize];
        let s = &bytes[keysize..keysize * 2];
        let dist = hamming(f, s).expect("no hamming") as f64 / keysize as f64;
        key_scores.push((keysize, dist));
    }
    key_scores.sort_by(|&a, &b| float_cmp(a.1, b.1));
    let nedist = key_scores[0];
    println!("{:?}", key_scores);
    println!("keysize is {}. smallest normalized edit distance is {}.",
             nedist.0, nedist.1);

    for block in bytes.chunks(nedist.0) {
        println!("> {:?}", block);
    }
    println!("{}", bytes.len());
    let bytes_t = transpose(&bytes, nedist.0);
    for block in bytes_t {
        println!("{:?}", block);
    }
}

fn float_cmp(a: f64, b: f64) -> Ordering {
    a.partial_cmp(&b).expect("Some arguments to float_cmp weren't finite")
}

fn transpose(s: &[u8], width: usize) -> Vec<Vec<u8>> {
    let mut buffer = Vec::new();
    for i in 0..width {
        let chunk: Vec<u8> = s
            .iter()
            .skip(i)
            .step(width)
            .cloned()
            .collect();
        buffer.push(chunk);
    }
    buffer
}

fn hamming(a: &[u8], b: &[u8]) -> Option<u64> {
    fixed_xor(a, b).map(|v|
        v.iter().map(|x| u64::from(x.count_ones())).sum()
    )
}

fn repeating_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    bytes.iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect()
}

fn decrypt_single_byte_xor(bytes: &[u8]) -> Result<(String, u8), std::str::Utf8Error> {
    let mut best_score = (0, std::f32::INFINITY);
    for key in 1..127 {
        let ch = vec![key; bytes.len()];
        let x = fixed_xor(bytes, &ch).expect("ack");
        let plaintext = str::from_utf8(&x)?;
        let s = score(plaintext);
        if best_score.1 > s {
            best_score = (key, s);
        }
    }

    let w = fixed_xor(bytes, &vec![best_score.0; bytes.len()]).unwrap();
    str::from_utf8(&w).map(|x| (x.to_owned(), best_score.0))
}

fn score(s: &str) -> f32 {
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

fn diff(v1: &[f32], v2: &[f32]) -> Option<f32> {
    if v1.len() != v2.len() {
        None
    }
    else {
        Some(zip(v1, v2)
            .map(|(a, b)| (a - b).abs())
            .sum())
    }
}

fn histo(s: &str) -> Vec<f32> {
    let mut v = vec![0.0; 26];
    for ix in s.bytes().filter_map(alph) {
        v[ix as usize] += 1.0 / s.len() as f32;
    }
    v
}

fn alph(c: u8) -> Option<u8> {
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

fn fixed_xor(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    if a.len() != b.len() {
        None
    }
    else {
        Some(zip(a, b).map(|(a, b)| a ^ b).collect())
    }
}

fn base16_decode(contents: &str) -> Vec<u8> {
    let mut bytes = Vec::<u8>::new();
    for byte in contents.as_bytes().chunks(2) {
        let s = str::from_utf8(byte).unwrap();
        if let Ok(n) = u8::from_str_radix(s, 16) {
            bytes.push(n);
        }
    }
    bytes
}

fn base16_encode(data: &[u8]) -> String {
    let table = b"0123456789abcdef";
    let mut encoded = String::new();
    for byte in data {
        let up = byte / 16;
        let down = byte % 16;
        let out = [table[up as usize], table[down as usize]];
        encoded.push_str(str::from_utf8(&out).unwrap());
    }
    encoded
}

// warning: this sucks
fn base64_encode(data: &[u8]) -> Vec<u8> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::new();
    for triplet in data.chunks(3) {
        let out = match *triplet {
            [a] => {
                let bits = a as usize * 256 * 256;
                [ table[ bits >> 18      ]
                , table[(bits >> 12) % 64]
                , 61
                , 61
                ]
            },
            [a,b] => {
                let bits = a as usize * 256 * 256 + b as usize * 256;
                [ table[ bits >> 18      ]
                , table[(bits >> 12) % 64]
                , table[(bits >> 6 ) % 64]
                , 61
                ]
            },
            [a,b,c] => {
                let bits = a as usize * 256 * 256 + b as usize * 256 + c as usize;
                [ table[ bits >> 18      ]
                , table[(bits >> 12) % 64]
                , table[(bits >> 6 ) % 64]
                , table[ bits        % 64]
                ]
            },
            _ => {
                unreachable!()
            },
        };
        encoded.extend(out.iter().cloned());
    }
    encoded
}

fn base64_decode(data: &[u8]) -> Vec<u8> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut decoded = Vec::<u8>::new();
    for quartet in data.chunks(4) {
        let indices: Vec<u8> = quartet
            .iter()
            .map(|x| table.iter().position(|y| y == x))
            .filter_map(|x| x)
            .map(|x| x as u8)
            .collect();

        // Convert the four 6-bit indices into three bytes,
        // fewer if there were any `=`s
        let v =
            [(*indices.get(0).unwrap_or(&0) << 2) + (*indices.get(1).unwrap_or(&0) >> 4)
            ,(*indices.get(1).unwrap_or(&0) << 4) + (*indices.get(2).unwrap_or(&0) >> 2)
            ,(*indices.get(2).unwrap_or(&0) << 6) + (*indices.get(3).unwrap_or(&0))
            ];

        // There's probably a better way to do this?
        let mut octets = Vec::<u8>::new();
        for x in v.iter().take(indices.len() - 1) {
            octets.push(*x);
        }

        decoded.append(&mut octets);
    }
    decoded
}
