use aes::*;
use blockmode::*;
use codec::*;
use xor::*;

use rand;
use rand::Rng;
use std::str::from_utf8;

pub fn set_3() {
    println!("Set 3");
    _17();
    _18();
    _19();
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
        cbc_encrypt(AES128, pt, &self.aes_key, &self.iv)
    }

    pub fn get_iv(&self) -> [u8; 16] {
        self.iv
    }

    // Consume a ciphertext, decrypt it, and return true or false depending on 
    // whether the padding is valid.
    pub fn verify_aes_128_cbc(&self, bytes: &[u8]) -> bool {
        cbc_decrypt(AES128, bytes, &self.aes_key, &self.iv).is_ok()
    }
}

// Just decrypt one block, given its predecessor
fn cbc_padding_attack_block(block: &[u8], server: &CBCServer, prev: &[u8]) -> Vec<u8> {
    let mut known_bytes = vec![0; 16];

    let mut test_ct = Vec::new();
    test_ct.extend_from_slice(prev);
    test_ct.extend_from_slice(block);
    assert!(test_ct.len() == 32);
    for col in (0..16).rev() { // from 15 down to 0 inclusive
        let pad = 16 - col as u8; // from 1 up to 16 inclusive
        for i in col+1..16 {
            test_ct[i] ^= pad ^ (pad - 1);
        }
        let mut valid_found = false;
        let orig = test_ct[col];
        for guess in 0..=255 {
            test_ct[col] = guess;
            let maybe_valid = server.verify_aes_128_cbc(&test_ct);
            // It's possible that the padding isn't what we think it is, so
            // mutate the preceding byte in case it's interfering.
            if col > 0 {
                test_ct[col - 1] ^= 0x01;
            }
            let definitely_valid = maybe_valid && server.verify_aes_128_cbc(&test_ct);
            if col > 0 {
                test_ct[col - 1] ^= 0x01;
            }
            valid_found |= definitely_valid;
            if valid_found { // ...then we know that orig ^ guess = secret ^ pad
                let learned_byte = guess ^ orig ^ pad;
                println!("Learned byte {} (byte {}, guessed {})", char::from(learned_byte), learned_byte, guess);
                known_bytes[col] = learned_byte;
                break;
            }
        }
        assert!(valid_found, " valid_found failed when col={}", col);
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
    cbc_padding_attack(&enc, &server, server.get_iv());
}

fn _18() {
    let fuck = include_bytes!("../data/18.txt");
    let expected = include_bytes!("../data/18_result.txt");
    let dec = base64_decode(fuck).unwrap();
    let ans = ctr_encrypt(AES128, &dec, *b"YELLOW SUBMARINE", [0; 8]);
    assert_eq!(ans[..], expected[..]);
}

fn _19() {
    let key: [u8; 16] = rand::random();
    let plaintexts = include_bytes!("../data/19.txt")
        .split(|byte| byte == &b'\n')
        .map(|line| base64_decode(line).unwrap());
    let ciphertexts = plaintexts
        .map(|pt| ctr_encrypt(AES128, &pt, key, [0; 8]))
        .collect::<Vec<Vec<_>>>();

    let mut columns = Vec::new();
    for i in 0.. {
        columns.push(Vec::new());
        for ciphertext in &ciphertexts {
            if i < ciphertext.len() {
                columns[i].push(ciphertext[i]);
            }
        }
        if columns[i].len() == 0 {
            break;
        }
        let dec = decrypt_single_byte_xor(&columns[i]);
        println!("{:?}", dec);
    }
    for column in columns {
        println!("{:?}", column);
    }
}
