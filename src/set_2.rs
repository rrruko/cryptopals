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

    // Detect block size
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

    // Detect that oracle uses ecb
    let ecb_test = vec![b'A'; block_size * 2];
    let ecb_test_out = oracle(&ecb_test[..], key);
    assert_eq!(
        ecb_test_out[..block_size],
        ecb_test_out[block_size..block_size * 2]);

    // Break it
    let mut known_bytes = Vec::new();

    'outer: for block_ix in 0.. {
        for offs in 1..=block_size {
            let pad_width = block_size - offs;
            let mut padding = vec![b'A'; pad_width];

            // Make a dictionary of possible values for this block.
            //
            // here, we only need to pass ONE BLOCK into the oracle.
            // We just need to make sure the first block_size - 1 bytes of
            // that block are equal to the first block_size - 1 bytes of the
            // `actual` block we define later.
            let mut dictionary = HashMap::new();
            
            let mut d = vec![b'A'; block_size];
            d.extend_from_slice(&known_bytes[..]);
            let mut dict_padding = Vec::new();
            let slice_start = block_ix * block_size + offs;
            dict_padding.extend_from_slice(&d[slice_start..slice_start + block_size - 1]);
            dict_padding.push(0);
            println!("{}", from_utf8(&dict_padding).unwrap());
            println!("pushing oracle({}?) for ? from 0 to 255", 
                from_utf8(&dict_padding[..block_size-1]).unwrap());
            for last_byte in 0..=255 {
                dict_padding[block_size - 1] = last_byte;
                let this_option = oracle(&dict_padding[..], key);
                dictionary.insert(last_byte, this_option[..block_size].to_vec());
            }

            // Get the actual value of the block.
            //
            // This will be 
            let actual = &oracle(&padding[..], key)[
                block_size * block_ix..
                block_size * (block_ix + 1)
            ];
            println!("actual = oracle({})", from_utf8(&padding[..]).unwrap());

            // Find the dictionary element that matches.
            let mut matched = false;
            for (k, v) in dictionary {
                println!("comparing {} to {}",
                    from_utf8(&base16_encode(&v[..])).unwrap(),
                    from_utf8(&base16_encode(&actual[..])).unwrap()
                );
                if v == actual {
                    matched = true;
                    println!("learned new byte {}", k);
                    known_bytes.push(k);
                }
            }
            if !matched {
                break 'outer;
            }
        }
        println!("{}", from_utf8(&known_bytes[..]).unwrap());
    }
}
