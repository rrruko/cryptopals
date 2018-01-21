use aes::*;
use codec::*;
use pkcs::*;

use std::str::from_utf8;

pub fn set_2() {
    _9();
    _10();
}

fn _9() {
    let x = b"YELLOW SUBMARINE";
    assert_eq!(b"YELLOW SUBMARINE\x04\x04\x04\x04", &pkcs7(x, 20).unwrap()[..]);
}

fn _10() {
    let file = include_bytes!("../data/10.txt");
    let dec = base64_decode(file);
    let res = aes128_cbc_decode_pad(&dec, *b"YELLOW SUBMARINE", [0; 16]).unwrap();
    assert_eq!(from_utf8(&res).unwrap(), include_str!("../data/7_result.txt"));
}
