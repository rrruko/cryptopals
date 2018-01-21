pub fn pkcs7(bytes: &[u8], new_length: usize) -> Option<Vec<u8>> {
    let diff = new_length - bytes.len();
    if diff > 0 && diff < 256 {
        let mut padded = vec![0; new_length];
        for i in 0..bytes.len() {
            padded[i] = bytes[i];
        }
        for i in bytes.len()..new_length {
            padded[i] = diff as u8;
        }
        Some(padded)
    } else {
        None
    }
}

pub fn undo_pkcs7(bytes: &[u8]) -> Vec<u8> {
    let padding_count = bytes[bytes.len() - 1] as usize;
    bytes[..bytes.len() - padding_count].to_vec()
}
