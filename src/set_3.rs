use aes::*;
use codec::*;

use rand;
use rand::Rng;
use std::io;
use std::str::from_utf8;

pub fn set_3() {
    _17();
}

struct CBCServer {
    aes_key: [u8; 16],
    iv: [u8; 16]
}

impl CBCServer {
    pub fn new() -> Self {
        CBCServer { 
            aes_key: rand::random(),
            iv:      rand::random()
        }
    }

    pub fn get_random_ciphertext(&self) -> Vec<u8> {
        let plaintexts = include_bytes!("../data/17.txt")
            .split(|byte| byte == &b'\n')
            .map(|line| base64_decode(line).unwrap())
            .collect::<Vec<_>>();
        let pt = rand::thread_rng().choose(&plaintexts).unwrap();
        aes128_cbc_encode_pad(pt, self.aes_key, self.iv)
    }

    pub fn get_iv(&self) -> [u8; 16] {
        self.iv
    }

    // Consume a ciphertext, decrypt it, and return true or false depending on 
    // whether the padding is valid.
    pub fn verify_aes_128_cbc(&self, bytes: &[u8]) -> bool {
        aes128_cbc_decode_pad(bytes, self.aes_key, self.iv).is_ok()
    }
}

// Just decrypt one block, given its predecessor
fn cbc_padding_attack_block(block: &[u8], server: &CBCServer, prev: &[u8]) -> Vec<u8> {
    let mut known_bytes = vec![0; 16];

    let mut test_ct = Vec::new();
    test_ct.extend_from_slice(prev);
    test_ct.extend_from_slice(block);
    // test_ct:
    //   AAAAAAAAAAAAAAAA
    //   ????????????????
    for col in (0..16).rev() { // from 15 down to 0 inclusive
        let pad = 16 - col as u8; // from 1 up to 16 inclusive
        for i in col+1..16 {
            test_ct[i] ^= pad ^ (pad - 1);
        }
        let mut valid_found = false;
        let orig = test_ct[col];
        for byte in 0..=255 {
            test_ct[col] = byte;
            valid_found |= server.verify_aes_128_cbc(&test_ct);
            if valid_found { // ...then we know that orig ^ byte = secret ^ pad
                let learned_byte = byte ^ pad ^ orig;
                println!("Learned byte {}", char::from(learned_byte));
                known_bytes[col] = learned_byte;
                break;
            }
        }
        assert!(valid_found);
    }
    println!("Learned block: {}", from_utf8(&known_bytes).unwrap());
    known_bytes
}

fn cbc_padding_attack(bytes: &[u8], server: &CBCServer, iv: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();

    let mut prev = Vec::new();
    prev.extend_from_slice(&iv);
    for block_index in 0..bytes.len()/16 {
        let mut block = Vec::new();
        block.extend_from_slice(&bytes[
            block_index*16..
            (block_index+1)*16
        ]);
        out.extend_from_slice(
            &cbc_padding_attack_block(&block, server, &prev)
        );
        prev = block;
    }

    out
}

fn _17() {
    let server = CBCServer::new();
    let enc = server.get_random_ciphertext();
    assert!(server.verify_aes_128_cbc(&enc));
    let ans = cbc_padding_attack(&enc, &server, server.get_iv());
}