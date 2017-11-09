#![feature(slice_patterns)]

extern crate cryptopals;

use std::char;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::option::Option;
use std::str;

const bar: &str = "--------------------------------";

fn main() {
    let t = "hel";
    let enc = base64_encode(&(t.bytes().collect::<Vec<u8>>())[..]);
    println!("enc: {:?}", enc);
    let dec = base64_decode(&enc.bytes().collect::<Vec<u8>>());
    println!("dec: {:?}", dec);
    println!("{}", bar);
    //println!("Trying challenge 6");
    //_6();
}

fn _1() {
    let mut file = File::open("./1.txt").expect("Couldn't open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Couldn't read to string");
    let contents = contents.trim();
    let bytes = base16_decode(contents.to_owned());
    println!("{}", base64_encode(bytes.as_slice()));
}

fn _2() {
    let xor1 = "1c0111001f010100061a024b53535009181c";
    let xor2 = "686974207468652062756c6c277320657965";
    let res  = "746865206b696420646f6e277420706c6179";

    let ans = fixed_xor(
        &base16_decode(xor1.to_owned()),
        &base16_decode(xor2.to_owned())
    ).unwrap();
    println!("{}", base16_encode(&ans[..]));
}

fn _3() {
    let code = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let bytes = base16_decode(code.to_owned());
    let ans = decrypt_single_byte_xor(&bytes);
    println!("{}", ans.unwrap_or("whoops".to_owned()));
}

fn _4() {
    let file = File::open("4.txt").unwrap();
    let buf_reader = BufReader::new(file);
    let l = buf_reader.lines();
    for line in l {
        let bytes = base16_decode(line.expect("no line"));
        match decrypt_single_byte_xor(&bytes) {
            Ok(res) => println!("{}", res),
            _       => ()
        }
    }
}

fn _5() {
    let inp: Vec<u8> = "h-hewwo??".bytes().collect();
    let key: Vec<u8> = "uwu".bytes().collect();
    let out = repeating_xor(&inp, &key);
    //let out2 = repeating_xor(&out, &key);
    println!("{}", from_ascii(&out).unwrap());
    println!("{}", base16_encode(&out[..]));
}

fn _6() {
    let test = hamming(&"this is a test".bytes().collect(),
                       &"wokka wokka!!!".bytes().collect());
    assert_eq!(test.unwrap(), 37);
    let mut file = File::open("6.txt").expect("no 6.txt");
    let mut base64_bytes: Vec<u8> = Vec::new();
    file.read_to_end(&mut base64_bytes);
    base64_bytes = base64_bytes.into_iter().filter(|&x| x > 32).collect();
    println!("{:?}", &base64_bytes);
    let mut bytes: Vec<u8> = base64_decode(&base64_bytes);
    println!("{:?}", bytes);
    let mut nedist = (1, std::f64::MAX);
    for keysize in 2..40 {
        let f = &bytes[0..keysize];
        let s = &bytes[keysize..keysize * 2];
        let dist = hamming(&f.to_vec(), &s.to_vec()).expect("no hamming") as f64 / keysize as f64;
        if dist < nedist.1 {
            nedist = (keysize, dist);
        }
        println!("f: {:?} \ns: {:?}", f, s);
    }
    //println!("{:?}", nedist);
}

fn hamming(a: &Vec<u8>, b: &Vec<u8>) -> Option<u64> {
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

fn repeating_xor(bytes: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..bytes.len() {
        let key_i = key[i % key.len()];
        out.push(bytes[i] ^ key_i);
    }
    out
}

fn decrypt_single_byte_xor<'a>(bytes: &'a Vec<u8>) -> Result<String, std::str::Utf8Error> {
    let mut best_score = (0, std::f32::INFINITY);
    for key in 1..127 {
        let ch = vec![key; bytes.len()];
        let x = fixed_xor(&bytes, &ch).expect("ack");
        let plaintext = from_ascii(&x)?;
        let s = score(plaintext.to_owned());
        if best_score.1 > s {
            best_score = (key, s);
        }
    }

    let w = fixed_xor(&bytes, &vec![best_score.0; bytes.len()]).unwrap();
    match from_ascii(&w) {
        Ok(res) => Ok(res.to_owned()),
        Err(e) => Err(e)
    }
}

fn from_ascii<'a>(v: &'a Vec<u8>) -> Result<&'a str, std::str::Utf8Error> {
    str::from_utf8(&v[..])
}

fn score(s: String) -> f32 {
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

fn histo(s: String) -> Vec<f32> {
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

fn fixed_xor(a: &Vec<u8>, b: &Vec<u8>) -> Option<Vec<u8>> {
    if a.len() != b.len() {
        None
    }
    else {
        let mut out = Vec::new();
        for i in 0..a.len() - 1 {
            out.push(a[i] ^ b[i]);
        }
        Some(out)
    }
}

fn base16_decode(contents: String) -> Vec<u8> {
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
    let table = "0123456789abcdef".as_bytes();
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
fn base64_encode(data: &[u8]) -> String {
    let table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();
    let mut encoded = String::new();
    println!("bytes in {:?}", data);
    for triplet in data.chunks(3) {
        let out = match triplet {
            &[a] => {
                let bits = a as usize * 256 * 256;
                [ *table.get( (bits >> 18)      ).unwrap()
                , *table.get(((bits >> 12) % 64)).unwrap()
                , 61
                , 61
                ]
            },
            &[a,b] => {
                let bits = a as usize * 256 * 256 + b as usize * 256;
                [ *table.get( (bits >> 18)      ).unwrap()
                , *table.get(((bits >> 12) % 64)).unwrap()
                , *table.get(((bits >> 6 ) % 64)).unwrap()
                , 61
                ]
            },
            &[a,b,c] => {
                let bits = a as usize * 256 * 256 + b as usize * 256 + c as usize;
                [ *table.get( (bits >> 18)      ).unwrap()
                , *table.get(((bits >> 12) % 64)).unwrap()
                , *table.get(((bits >> 6 ) % 64)).unwrap()
                , *table.get( (bits        % 64)).unwrap()
                ]
            },
            _ => {
                unreachable!()
            },
        };
        let chunk = str::from_utf8(&out[..]).expect("b64enc");
        encoded.push_str(chunk);
    }
    encoded
}

// FIXME: Doesn't handle trailing = properly
fn base64_decode(data: &Vec<u8>) -> Vec<u8> {
    let table: Vec<u8> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".bytes().collect();
    println!("{:?}", table);
    println!("bytes in: {:?}", data);
    let mut decoded = Vec::<u8>::new();
    for quartet in data.chunks(4) {
        // Each byte of input maps to an index in the table.
        // ABC= -> 0,1,2,None
        // 0,1,2,None -> 0,1,2,0
        let indices: Vec<u8> = quartet
            .iter()
            .map(|x| table.iter().position(|y| y == x).map(|p| p as u8))
            .map(|index| index.unwrap_or(0))
            .collect();
        
        // Convert the four 6-bit indices into three bytes.
        let octets: [u8; 3] =
            [(indices.get(0).unwrap() << 2) + (indices.get(1).unwrap() >> 4)
            ,(indices.get(1).unwrap() << 4) + (indices.get(2).unwrap() >> 2)
            ,(indices.get(2).unwrap() << 6) + (indices.get(3).unwrap())
            ];
        decoded.append(&mut octets.to_vec());
    }
    decoded
}
