use aes::*;
use codec::*;
use oracle::*;
use pkcs::*;

use std::str::from_utf8;

pub fn set_2() {
    _9();
    _10();
    _11();
    //_12();
}

fn _9() {
    let x = b"YELLOW SUBMARINE";
    assert_eq!(b"YELLOW SUBMARINE\x04\x04\x04\x04", &pkcs7(x, 20).unwrap()[..]);
}

fn _10() {
    let file = include_bytes!("../data/10.txt");
    let file = &file.iter().cloned()
        .filter(|&b| !char::from(b).is_whitespace())
        .collect::<Vec<u8>>()[..];

    let dec = base64_decode(file).unwrap();
    let res = aes128_cbc_decode_pad(&dec, *b"YELLOW SUBMARINE", [0; 16]).unwrap();
    assert_eq!(from_utf8(&res).unwrap(), include_str!("../data/7_result.txt"));
}

fn _11() {
    // There is exactly one pair of identical 16-byte chunks in this file,
    // so we can detect whether it's ECB-encrypted.
    let plaintext = include_bytes!("../data/7_result.txt");
    for _ in 0..10 {
        let (mystery, mode) = random_encrypt(plaintext);
        assert_eq!(ecb_cbc_oracle(&mystery[..]), mode);
    }
}

fn _12() {
   let unknown = base64_decode(include_bytes!("../data/12_unknown.txt"));
}
