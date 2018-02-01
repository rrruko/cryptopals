use aes::*;
use codec::*;
use oracle::*;
use pkcs::*;
use rand;

use nom::*;
use nom::IResult::*;
use nom::Needed::Size;

use std::collections::HashMap;
use std::str::from_utf8;
use std::io::Write;

pub fn set_2() {
    _9();
    _10();
    _11();
    _12();
    _13();
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

type Oracle = Fn(&[u8]) -> Vec<u8>;

fn ecb_block_size(ora: &Oracle) -> usize {
    let bytes = &[b'A'; 255];
    let mut out_length = None;
    let mut block_size = None;
    for i in 1..=255 {
        let enc = ora(&bytes[..i]);
        match out_length {
            Some(l) if enc.len() > l => {
                block_size = Some(enc.len() - l);
                break;
            }
            Some(_) => { },
            None => { out_length = Some(enc.len()); }
        }
    }
    block_size.unwrap()
}

fn is_ecb(ora: &Oracle, block_size: usize) -> bool {
    let ecb_test = vec![b'A'; block_size * 2];
    let ecb_test_out = ora(&ecb_test[..]);
    ecb_test_out[..block_size] == ecb_test_out[block_size..block_size * 2]
}

fn break_ecb_with_oracle(ora: &Oracle, block_size: usize) -> Vec<u8> {
    let mut known_bytes = Vec::new();

    'outer: for block_ix in 0.. {
        for offs in 1..=block_size {
            let pad_width = block_size - offs;
            let mut padding = vec![b'A'; pad_width];

            // Get the actual value of the block.
            let actual = &ora(&padding[..])[
                block_size * block_ix..
                block_size * (block_ix + 1)
            ];

            // Make a dictionary of possible values for this block.
            //
            // here, we only need to pass ONE BLOCK into the oracle.
            // We just need to make sure the first block_size - 1 bytes of
            // that block are equal to the first block_size - 1 bytes of the
            // plaintext of the `actual` block.
            let mut d = vec![b'A'; block_size];
            d.extend_from_slice(&known_bytes[..]);
            let mut dict_padding = Vec::new();
            let slice_start = block_ix * block_size + offs;
            dict_padding.extend_from_slice(&d[slice_start..slice_start + block_size - 1]);
            dict_padding.push(0);
            let mut matched = false;
            for last_byte in 0..=255 {
                dict_padding[block_size - 1] = last_byte;
                let this_option = ora(&dict_padding[..]);
                if &this_option[..block_size] == actual {
                    matched = true;
                    /*print!("{}", char::from(last_byte));
                    ::std::io::stdout().flush().unwrap();*/
                    known_bytes.push(last_byte);
                    break;
                }
            }
            if !matched {
                break 'outer;
            }
        }
    }
    known_bytes
}

fn _12() {
    // Get block size
    let key: [u8; 16] = rand::random();

    let unknown = base64_decode_filter(
        include_bytes!("../data/12.txt"));

    let ora: &Oracle = &(move |buffer| {
        let mut v = Vec::new();
        v.extend_from_slice(buffer);
        v.extend_from_slice(&unknown[..]);
        aes128_ecb_encode_pad(&v[..], key)
    });
    let block_size = ecb_block_size(ora);

    // Detect that oracle uses ecb
    assert!(is_ecb(ora, block_size));

    // Break it
    let answer = break_ecb_with_oracle(ora, block_size);
    println!("{}", from_utf8(&answer[..]).unwrap());
}

type KVVec<'a, 'b> = Vec<(&'a [u8], &'b [u8])>;

named!(key,
    take_until_and_consume!(&b"="[..]));
named!(value,
    take_until_and_consume!(&b"&"[..]));
named!(kvpair< (&[u8], &[u8]) >,
    tuple!(key, value));
named!(kvs<KVVec>, many0!(kvpair));

fn sanitize(bytes: &[u8]) -> Vec<u8> {
    bytes.iter()
        .cloned()
        .filter(|&ch| ch != b'=' && ch != b'&')
        .collect()
}

fn mk_profile(email: &[u8]) -> KVVec {
    let mut h = Vec::new();
    h.push((&b"email"[..], &email[..]));
    h.push((&b"uid"[..],   &b"10"[..]));
    h.push((&b"role"[..],  &b"user"[..]));
    h
}

fn url_encode(obj: KVVec) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in obj {
        out.extend_from_slice(k);
        out.push(b'=');
        out.extend_from_slice(v);
        out.push(b'&');
    }
    out.pop();
    out
}

fn mk_encrypted_url_profile(email: &[u8], key: [u8; 16]) -> Vec<u8> {
    let obj = mk_profile(email);
    let url = url_encode(obj);
    //println!("encrypting: {}", from_utf8(&url[..]).unwrap());
    aes128_ecb_encode_pad(&url[..], key)
}

fn pretty_ct(ciphertext: &[u8]) {
    for chunk in ciphertext.chunks(16) {
        print!("{} ", from_utf8(&base16_encode(chunk)[..]).unwrap());
    }
    println!("");
}

// This is hardcoded for _13 because I'm too lazy to write it right now
// It looks like challenge 14 is mostly about implementing this function so
// I'll do it then
fn prefix_length(oracle: &Oracle) -> usize {
    6
}

// Everything here is hardcoded because I'm lazy but you can do this even if
// you don't know the prefix (which in this case is `email=`) and you could
// decode the entire postfix to determine that the padding on `to` needs to
// be 13
fn _13() {
    let key = rand::random();
    let oracle: &Oracle = &(move |bytes| {
        let mut v = Vec::new();
        v.extend_from_slice(bytes);
        mk_encrypted_url_profile(&v[..], key)
    });

    let block_size = ecb_block_size(oracle);
    let prefix_length = prefix_length(oracle);

    let pad_length = block_size - (prefix_length % block_size);
    let pad_blocks = 1 + (prefix_length / block_size);

    // We're setting our email address such that one of the blocks of the
    // ciphertext will be "admin", padded using EKCS7.
    // Since we computed the prefix length, we know exactly which
    // ciphertext block that is.
    let mut evil_email = vec![b'A'; pad_length];
    evil_email.extend_from_slice(
        b"admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
    );
    let evil = oracle(&evil_email[..]);

    pretty_ct(&evil[..]);

    // We're setting our email address such that the last block of the
    // ciphertext will be "user____________" (EKCS7 padded) as in "role=user"
    // Since we just figured out the ciphertext of "admin___________" (EKCS7
    // padded), we can just paste it over that last block and the result will
    // decrypt successfully.
    let mut to = oracle(&[b'A'; 13][..]);
    let last = to.len() - 16;
    to[last..].copy_from_slice(&evil[pad_blocks*block_size..(pad_blocks+1)*block_size]);

    pretty_ct(&to[..]);

    let dec = aes128_ecb_decode_pad(&to[..], key).unwrap();
    println!("{}", from_utf8(&dec[..]).unwrap());
    match kvs(&dec) {
        Done(_, o) => println!("{:?}", o),
        _ => println!("failed")
    }
}
