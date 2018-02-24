pub fn pkcs7(bytes: &[u8], new_length: usize) -> Option<Vec<u8>> {
    let diff = new_length - bytes.len();
    if diff > 0 && diff < 256 {
        let mut padded = vec![diff as u8; new_length];
        padded[..bytes.len()].clone_from_slice(bytes);
        Some(padded)
    } else {
        None
    }
}

pub fn undo_pkcs7(bytes: &[u8]) -> Vec<u8> {
    let padding_count = bytes[bytes.len() - 1] as usize;
    bytes[..bytes.len() - padding_count].to_vec()
}

pub fn undo_pkcs7_checked(bytes: &[u8]) -> Option<Vec<u8>> {
    let padding_count = bytes[bytes.len() - 1] as usize;
    if padding_count == 0 || padding_count > bytes.len() {
        return None;
    }
    for item in &bytes[bytes.len() - padding_count..] {
        if *item != padding_count as u8 {
            return None;
        }
    }
    Some(bytes[..bytes.len() - padding_count].to_vec())
}
