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
    /*
    _9();
    _10();
    _11();
    */
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
            Some(l) => { },
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
                    print!("{}", char::from(last_byte));
                    ::std::io::stdout().flush();
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
        {
            aes128_ecb_encode_pad(&v[..], key)
        }
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

fn mk_profile(email: &[u8]) -> HashMap<&[u8], &[u8]> {
    let mut h = HashMap::new();
    h.insert(&b"email"[..], &email[..]);
    h.insert(&b"uid"[..],   &b"10"[..]);
    h.insert(&b"role"[..],  &b"user"[..]);
    h
}

fn url_encode(kvs: HashMap<&[u8], &[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in kvs {
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
    aes128_ecb_encode_pad(&url[..], key)
}

fn _13() {
    let input = b"foo=bar&baz=qux&zap=zazzle&";
    let email = sanitize(b"ruk=&o@gmail.com&");
    let emailEnc =
        [(&b"email"[..], &b"ruko@gmail.com"[..]),
         (&b"uid"[..],   &b"10"[..]),
         (&b"role"[..],  &b"user"[..])].iter().cloned().collect();
    assert_eq!(
        mk_profile(&email[..]),
        emailEnc
    );
    match kvs(input) {
        Done(i, o)          => println!("{:?}", o),
        Error(_)            => println!(":("),
        Incomplete(Size(n)) => println!(":( {}", n),
        Incomplete(_)       => println!("incomplete"),
        _                   => println!("WOAH")
    };
    let key = rand::random();
    mk_encrypted_url_profile(b"ruko@gmail.com", key);
}
