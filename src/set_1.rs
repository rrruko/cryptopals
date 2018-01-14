use aes::*;
use codec::*;
use stats::*;
use xor::*;

use std::cmp::Ordering;
use std::f32::INFINITY;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::str::from_utf8;
use itertools::Itertools;

pub fn set_1() {
    _1();
    _2();
    _3();
    _4();
    _5();
    _6();
    _7();
}

fn _1() {
    let mut file = File::open("data/1.txt").expect("no 1.txt");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Couldn't read to string");
    let contents = contents.trim().as_bytes();
    let bytes = base16_decode(contents);
    let base64enc = base64_encode(bytes.as_slice());

    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        from_utf8(&base64enc).unwrap());
}

fn _2() {
    let xor1 = b"1c0111001f010100061a024b53535009181c";
    let xor2 = b"686974207468652062756c6c277320657965";
    let res  = b"746865206b696420646f6e277420706c6179";

    let ans = fixed_xor(
        &base16_decode(xor1),
        &base16_decode(xor2)
    ).unwrap();

    assert_eq!(base16_encode(&ans)[..], res[..]);
}

fn _3() {
    let code = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let bytes = base16_decode(code);
    let ans = decrypt_single_byte_xor(&bytes).0;

    assert_eq!("Cooking MC's like a pound of bacon",
        from_utf8(&ans).unwrap());
}

fn _4() {
    let file = File::open("data/4.txt").expect("no 4.txt");
    let buf_reader = BufReader::new(file);
    let l = buf_reader.lines();
    let mut best_rated = (INFINITY, String::new());
    for line in l {
        let bytes = base16_decode(line.expect("no line").as_bytes());
        let res = decrypt_single_byte_xor(&bytes).0;
        let this_score = score(&res);
        if let Ok(string) = from_utf8(&res) {
            let printable: Vec<u8> = string.bytes()
                .filter(|ch| !char::is_control(*ch as char)).collect();
            if this_score < best_rated.0 {
                best_rated =
                    (this_score, from_utf8(&printable).unwrap().to_string());
            }
        }
    }

    assert_eq!(best_rated.1, "nOWTHATTHEPARTYISJUMPING*");
}

fn _5() {
    let raw = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";

    let enc = repeating_xor(raw, key);
    let expected = include_bytes!("../data/5_result.txt");

    assert_eq!(enc, base16_decode(expected));

    let dec = repeating_xor(&enc, key);

    assert_eq!(raw[..], dec[..]);
}

fn _6() {
    let mut file = File::open("data/6.txt").expect("no 6.txt");
    let mut base64_bytes = Vec::new();
    file.read_to_end(&mut base64_bytes).unwrap();
    base64_bytes = base64_bytes.into_iter().filter(|&x| x > 32).collect();
    let bytes = base64_decode(&base64_bytes);
    let mut key_scores = Vec::<(usize, f64)>::new();
    for keysize in 2..40 {
        let f = &bytes[0..keysize];
        let s = &bytes[keysize..keysize * 2];
        let dist = hamming(f, s).expect("no hamming") as f64 / keysize as f64;
        key_scores.push((keysize, dist));
    }
    key_scores.sort_by(|&a, &b| float_cmp(a.1, b.1));

    let mut results: Vec<Vec<u8>> = Vec::new();
    for (keysize, _) in key_scores {
        let bytes_t = transpose(&bytes, keysize);
        let the_key: Vec<u8> =
            bytes_t
                .iter()
                .map(|block| decrypt_single_byte_xor(block).1)
                .collect();

        let dec: Vec<u8> = repeating_xor(&bytes, &the_key)
                .into_iter().filter(|ch| !char::is_control(*ch as char)).collect();

        results.push(dec);
    }
    results.sort_by(|x, y| float_cmp(f64::from(score(x)), f64::from(score(y))));

    let answer = from_utf8(&results[0]).unwrap();

    assert_eq!(answer, include_str!("../data/6_result.txt"));
}

fn _7() {
    let key = b"YELLOW SUBMARINE";
    let enc = base64_decode(include_bytes!("../data/7.txt"));
    let dec = aes128_ecb_decode_pad(&enc[..], *key).unwrap();
    let res = include_bytes!("../data/7_result.txt");
    assert_eq!(dec[..], res[..]);
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
