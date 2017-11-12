#![feature(slice_patterns)]

extern crate cryptopals;
extern crate itertools;

use std::char;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::option::Option;
use std::str;
use std::vec::Vec;
use itertools::Itertools;

const BAR: &str = "--------------------------------";

fn main() {
    test();
}

fn test() {
    //test_transpose();
    test_base64();
    _1();
    _2();
    _3();
    _4();
    _5();
    _6();
}

fn test_base64() {
    identity("Ringo mogire beam");
    identity("Ringo mogire beam!");
    identity("Ringo mogire beam!!");
}

fn identity(v: &str) {
    let vbytes = v.bytes().collect::<Vec<u8>>();
    let enc = base64_encode(&vbytes[..]);
    let dec = base64_decode(&enc.bytes().collect::<Vec<u8>>());
    assert_eq!(vbytes, dec);
}

fn _1() {
    let mut file = File::open("./1.txt").expect("Couldn't open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Couldn't read to string");
    let contents = contents.trim();
    let bytes = base16_decode(contents);
    let base64enc = base64_encode(bytes.as_slice());
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        base64enc);
}

fn _2() {
    let xor1 = "1c0111001f010100061a024b53535009181c";
    let xor2 = "686974207468652062756c6c277320657965";
    let res  = "746865206b696420646f6e277420706c6179";

    let ans = fixed_xor(
        &base16_decode(xor1),
        &base16_decode(xor2)
    ).unwrap();
    assert_eq!(base16_encode(&ans[..]), res);
}

fn _3() {
    let code = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let bytes = base16_decode(code);
    let ans = decrypt_single_byte_xor(&bytes).unwrap().0;
    assert_eq!("Cooking MC's like a pound of bacon", ans);
}

fn _4() {
    let file = File::open("4.txt").unwrap();
    let buf_reader = BufReader::new(file);
    let l = buf_reader.lines();
    for line in l {
        let bytes = base16_decode(&line.expect("no line")[..]);
        if let Ok(res) = decrypt_single_byte_xor(&bytes) {
            println!("{}", res.0);
        }
    }
}

fn _5() {
    let raw = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";

    let enc = repeating_xor(&raw[..], &key[..]);
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(enc[..], base16_decode(expected)[..]);

    let dec = repeating_xor(&enc, &key[..]);
    assert_eq!(raw[..], dec[..]);
}

fn _6() {
    let test = hamming(&"this is a test".bytes().collect::<Vec<u8>>()[..],
                       &"wokka wokka!!!".bytes().collect::<Vec<u8>>()[..]);
    assert_eq!(test.unwrap(), 37);
    let mut file = File::open("6.txt").expect("no 6.txt");
    let mut base64_bytes: Vec<u8> = Vec::new();
    file.read_to_end(&mut base64_bytes);
    base64_bytes = base64_bytes.into_iter().filter(|&x| x > 32).collect();
    println!("{:?}", &base64_bytes);
    let bytes: Vec<u8> = base64_decode(&base64_bytes);
    println!("{:?}", bytes);
    let mut key_scores = Vec::<(usize, f64)>::new();
    let mut nedist = (1, std::f64::MAX);
    for keysize in 2..40 {
        let f = &bytes[0..keysize];
        let s = &bytes[keysize..keysize * 2];
        let dist = hamming(f, s).expect("no hamming") as f64 / keysize as f64;
        key_scores.push((keysize, dist));
    }
    println!("{:?}", key_scores);
    return;
    println!("keysize is {}. smallest normalized edit distance is {}.",
             nedist.0, nedist.1);

    for block in bytes.chunks(nedist.0) {
        println!("> {:?}", block);
    }
    let bytesT = transpose(&bytes[..], nedist.0);
    let mut the_key = Vec::<u8>::new();
    for block in bytesT.chunks(bytesT.len()/nedist.0) {
       let key = decrypt_single_byte_xor(block).unwrap().1;
       the_key.push(key);
    }
    println!("{}", str::from_utf8(&the_key[..]).unwrap());
    let dec = repeating_xor(&bytes[..], &the_key[..]);
    //println!("{}", str::from_utf8(&dec[..]).unwrap());
}

fn transpose(s: &[u8], width: usize) -> Vec<u8> {
    let mut buffer = Vec::new();
    for i in 0..width {
        let mut chunk: Vec<u8> = s
            .iter()
            .skip(i)
            .step(width)
            .map(|x| x.clone())
            .collect();
        buffer.append(&mut chunk);
    }
    buffer
}

fn test_transpose() {
    test_transpose_2(&[0], 2);
    test_transpose_2(&[0, 1], 2);
    test_transpose_2(&[0, 1, 2], 2);
    test_transpose_2(&[0, 1, 2, 3], 2);
    test_transpose_2(&[0], 3);
    test_transpose_2(&[0, 1], 3);
    test_transpose_2(&[0, 1, 2], 3);
    test_transpose_2(&[0, 1, 2, 3], 3);
}

// This checks that a transpose is invertible, which I don't think is actually
// true for non-rectangular "matrices" like the ones I'm working with
// So not really a good test
fn test_transpose_2(v: &[u8], width: usize) {
    let height = (v.len() - 1) / width + 1;
    let vT = transpose(&v[..], width);
    let vTT = transpose(&vT[..], height);
    assert_eq!(v, &vTT[..]);
}

fn hamming(a: &[u8], b: &[u8]) -> Option<u64> {
    let mut sum = 0;
    if a.len() != b.len() {
        None
    }
    else {
        for i in 0..a.len() {
            sum += (a[i] ^ b[i]).count_ones() as u64;
        }
        Some(sum)
    }
}

fn repeating_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..bytes.len() {
        let key_i = key[i % key.len()];
        out.push(bytes[i] ^ key_i);
    }
    out
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

    let w = fixed_xor(&bytes, &vec![best_score.0; bytes.len()]).unwrap();
    str::from_utf8(&w).map(|x| (x.to_owned(), best_score.0))
}

fn score(s: &str) -> f32 {
    let english_freq = vec![
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
    diff(histo(s), english_freq).unwrap()
}

fn diff(v1: Vec<f32>, v2: Vec<f32>) -> Option<f32> {
    if v1.len() != v2.len() {
        None
    }
    else {
        let mut del = 0.0;
        for i in 0..v1.len() - 1 {
            del += (v1[i] - v2[i]).abs()
        }
        Some(del)
    }
}

fn histo(s: &str) -> Vec<f32> {
    let mut v = vec![0.0; 26];
    for ch in s.chars() {
        if let Some(ix) = alph(&ch) {
            v[ix as usize] += 1.0 / s.len() as f32;
        }
    }
    v
}

fn alph(c: &char) -> Option<u8> {
    let ch = *c as u8;
    if ch >= 65 && ch <= 90 {
        Some(ch - 65)
    }
    else if ch >= 97 && ch <= 122 {
        Some(ch - 97)
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
        let mut out = Vec::new();
        for i in 0..a.len() {
            out.push(a[i] ^ b[i]);
        }
        Some(out)
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
        encoded.push_str(str::from_utf8(&out[..]).unwrap());
    }
    encoded
}

// warning: this sucks
// also, maybe this shouldn't return a String?
fn base64_encode(data: &[u8]) -> String {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
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
        let chunk = str::from_utf8(&out[..]).unwrap();
        encoded.push_str(chunk);
    }
    encoded
}

fn base64_decode(data: &[u8]) -> Vec<u8> {
    let table: Vec<u8> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".bytes().collect();
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
        let v: [u8; 3] =
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
