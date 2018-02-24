use pkcs::*;

use byteorder::{ByteOrder, LittleEndian};
use itertools::zip;

type Result = ::std::result::Result<Vec<u8>, &'static str>;

pub trait BlockCipher: Copy {
    fn encrypt(&self, &[u8], &[u8]) -> Vec<u8>;
    fn decrypt(&self, &[u8], &[u8]) -> Vec<u8>;
    fn block_size(&self) -> usize;
}

// The input data is padded to the next multiple of `block_size` above its
// actual length. That is, if the length is perfectly divisible by the block
// size, we pad with 0x10 `block_size` times. Otherwise, we pad with the number
// of missing bytes; e.g. if the last chunk of the input is [8, 6, 7, 5, 3, 0,
// 9], there are 9 missing bytes, so it is padded to [8, 6, 7, 5, 3, 0, 9, 9,
// 9, 9, 9, 9, 9, 9, 9, 9].
pub fn ecb_encrypt<T>(cipher: &T, pt: &[u8], key: &[u8]) -> Vec<u8>
    where T: BlockCipher {
    let block_size = cipher.block_size();
    let new_length = ((pt.len() / block_size) + 1) * block_size;
    let padded = pkcs7(pt, new_length).unwrap();
    let mut out = Vec::<u8>::new();
    for chunk in padded.chunks(block_size) {
        let enc = cipher.encrypt(chunk, key);
        out.extend(enc);
    }
    out
}

pub fn ecb_decrypt<T>(cipher: &T, ct: &[u8], key: &[u8]) -> Result
    where T: BlockCipher {
    let block_size = cipher.block_size();
    if ct.len() % block_size != 0 {
        return Err("Ciphertext length was not a multiple of the block size. \
            It may not have been padded before encryption.")
    }
    let mut out = Vec::<u8>::new();
    for chunk in ct.chunks(block_size) {
        let dec = cipher.decrypt(chunk, key);
        out.extend(dec);
    }
    Ok(undo_pkcs7(&out))
}

pub fn cbc_encrypt<T>(cipher: &T, pt: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8>
    where T: BlockCipher {
    let block_size = cipher.block_size();
    let new_length = ((pt.len() / block_size) + 1) * block_size;
    let padded = pkcs7(pt, new_length).unwrap();
    let mut out = Vec::<u8>::new();
    let mut prev = vec![0; block_size];
    prev.copy_from_slice(iv);
    for chunk in padded.chunks(block_size) {
        let mut buf = vec![0; block_size];
        for i in 0..buf.len() {
            buf[i] = chunk[i] ^ prev[i];
        }
        let enc = cipher.encrypt(&buf, key);
        out.extend(&enc);
        prev.copy_from_slice(&enc);
    }
    out
}

pub fn cbc_decrypt<T>(cipher: &T, ct: &[u8], key: &[u8], iv: &[u8]) -> Result
    where T: BlockCipher {
    let block_size = cipher.block_size();
    if ct.len() % block_size != 0 {
        return Err("Input length was not a multiple of 16.")
    }
    let mut out = Vec::<u8>::new();
    let mut prev = vec![0; block_size];
    prev.copy_from_slice(iv);
    for chunk in ct.chunks(block_size) {
        let mut dec = cipher.decrypt(chunk, key);
        for i in 0..dec.len() {
            dec[i] ^= prev[i];
        }
        out.extend(dec);
        prev.copy_from_slice(chunk);
    }
    match undo_pkcs7_checked(&out) {
        Some(res) => Ok(res),
        None      => Err("Invalid padding")
    }
}

fn get_ctr_keystream<T>(cipher: &T, key: [u8; 16], nonce: [u8; 8], ctr: u64) -> [u8; 16]
    where T: BlockCipher {
    let mut buf = [0; 16];
    buf[..8].copy_from_slice(&nonce[..]);
    LittleEndian::write_u64(&mut buf[8..], ctr);
    let keystream = cipher.encrypt(&buf, &key);
    buf.copy_from_slice(&keystream[..]);
    buf
}

pub fn ctr_encrypt<T>(cipher: &T, bytes: &[u8], key: [u8; 16], nonce: [u8; 8]) -> Vec<u8>
    where T: BlockCipher {
    let mut out = Vec::<u8>::new();
    for (block_ix, chunk) in bytes.chunks(16).enumerate() {
        let keystream = get_ctr_keystream(cipher, key, nonce, block_ix as u64);
        let ct: Vec<u8> = zip(chunk.iter(), &keystream).map(|(i, j)| i ^ j).collect();
        out.extend(&ct);
    }
    out
}
