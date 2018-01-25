use aes::*;
use codec::*;
use oracle::*;
use pkcs::*;
use rand;

use std::collections::HashMap;
use std::str::from_utf8;

pub fn set_2() {
    _9();
    _10();
    _11();
    _12();
}

fn _9() {
    let x = b"YELLOW SUBMARINE";
    assert_eq!(b"YELLOW SUBMARINE\x04\x04\x04\x04", &pkcs7(x, 20).unwrap()[..]);
}

fn _10() {
    let file = include_bytes!("../data/10.txt");
    let dec = base64_decode_filter(file);
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

fn oracle(buffer: &[u8], key: [u8; 16]) -> Vec<u8> {
    let unknown = &base64_decode_filter(
        include_bytes!("../data/12.txt"))[..];
    let mut v = Vec::new();
    v.extend_from_slice(buffer);
    v.extend_from_slice(unknown);
    {
        aes128_ecb_encode_pad(&v[..], key)
    }
}

fn _12() {
    let key: [u8; 16] = rand::random();

    // detect block size
    let bytes = &[b'A'; 20];
    let mut out_length = None;
    let mut block_size = None;
    for i in 1..20 {
        let enc = &oracle(&bytes[..i], key);
        match out_length {
            None    => {
                out_length = Some(enc.len());
            },
            Some(l) if enc.len() > l => {
                block_size = Some(enc.len() - l);
                break;
            },
            _ => { }
        }
    };
    let block_size = block_size.unwrap();

    // detect that oracle uses ecb
    let ecb_test = vec![b'A'; block_size * 2];
    let ecb_test_out = oracle(&ecb_test[..], key);
    assert_eq!(
        ecb_test_out[..block_size],
        ecb_test_out[block_size..block_size * 2]);

    //
    let mut known_bytes = Vec::new();

    for offs in 0..16 {
        let mut seen = HashMap::new();
        let mut brute_force = vec![b'A'; block_size];
        
        let short = &oracle(&vec![b'A'; block_size - 1 - offs][..], key)[..block_size];

        for i in 0..known_bytes.len() {
            brute_force[block_size - 1 - offs + i] = known_bytes[i];
        }
        println!("brute_force[0..block_size-1] is {:?}", &brute_force[0..block_size-1]);

        for last_byte in 0..=255 {
            brute_force[block_size - 1] = last_byte;
            seen.insert(
                last_byte, 
                oracle(&brute_force[..], key)[..block_size].to_vec()
            );
        }
        for (k, v) in seen {
            if v == short {
                println!("learned new byte {}", k);
                known_bytes.push(k);
            }
        }
    }

    println!("{}", from_utf8(&known_bytes[..]).unwrap());
}

fn hell(x: &[u8]) -> Vec<u8> {
    x.clone().to_vec()
}

fn wtf() {
    let a = &[0; 16];
    let b = hell(a);
    let c = hell(&b[..]).clone();
    println!("{:?}", c);
}
