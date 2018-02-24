use aes::*;
use blockmode::*;
use rand;
use rand::distributions::{IndependentSample, Range};
use std::collections::HashSet;

#[derive(Debug)]
pub enum Mode {
    ECB,
    CBC
}

// good grief
impl PartialEq for Mode {
    fn eq(&self, other: &Mode) -> bool {
        match (self, other) {
            (&Mode::ECB, &Mode::ECB) | (&Mode::CBC, &Mode::CBC) => true,
            _ => false
        }
    }
}

impl Eq for Mode {}

fn random_pad(bytes: &[u8]) -> Vec<u8> {
    let five_to_ten = Range::new(5usize, 10);
    let mut rng = rand::thread_rng();
    let pre = five_to_ten.ind_sample(&mut rng);
    let post = five_to_ten.ind_sample(&mut rng);

    let total_length = pre + bytes.len() + post;

    let mut buffer = Vec::with_capacity(total_length);

    for _ in 0..pre {
        buffer.push(rand::random());
    }
    
    buffer.extend(bytes);
    
    for _ in 0..post {
        buffer.push(rand::random());
    }
    
    buffer
}

pub fn random_encrypt(plaintext: &[u8]) -> (Vec<u8>, Mode) {
    let random_key: [u8; 16] = rand::random();
    let padded = random_pad(plaintext);
    let iv: [u8; 16] = rand::random();
    if rand::random() {
        (ecb_encrypt(AES128, &padded, &random_key),      Mode::ECB)
    } else {
        (cbc_encrypt(AES128, &padded, &random_key, &iv), Mode::CBC)
    }
}

// Check for any duplicated 16-byte chunks in a ciphertext.
// It's vanishingly unlikely to get any under CBC, so if we find any, ECB must 
// have been used. However, there must be duplicates in the plaintext in order
// to get duplicates in the ciphertext, so long plaintexts give better results.
pub fn ecb_cbc_oracle(bytes: &[u8]) -> Mode {
    let mut found_dupes = false;
    for skip_amt in 0..16 {
        let bytes = &bytes[skip_amt..];
        let mut seen = HashSet::new();
        for chunk in bytes.chunks(16) {
            if !seen.insert(chunk) {
                found_dupes = true;
            }
        }
    }

    if found_dupes {
        Mode::ECB
    } else {
        Mode::CBC
    }
}
