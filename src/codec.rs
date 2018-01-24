use std::char;
use std::cmp::min;
use std::str::from_utf8;

pub fn base16_encode(data: &[u8]) -> Vec<u8> {
    let table = b"0123456789abcdef";
    let mut encoded = Vec::new();
    for byte in data {
        let up = byte / 16;
        let down = byte % 16;
        let out = [table[up as usize], table[down as usize]];
        encoded.extend(out.iter().cloned());
    }
    encoded

}

pub fn base16_decode(contents: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::<u8>::new();
    for byte in contents.chunks(2) {
        let s = from_utf8(byte).unwrap();
        if let Ok(n) = u8::from_str_radix(s, 16) {
            decoded.push(n);
        }
    }
    decoded
}

pub fn base64_encode(data: &[u8]) -> Vec<u8> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
        abcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::new();
    for triplet in data.chunks(3) {
        let mut out = [61; 4];
        let mut triplet_buf = [0; 3];
        for i in 0..triplet.len() {
            triplet_buf[i] = triplet[i];
        }
        let bits =
            triplet_buf[0] as usize * 256 * 256 +
            triplet_buf[1] as usize * 256 +
            triplet_buf[2] as usize;
        for i in 0..triplet.len() + 1 {
            out[i] = table[(bits >> (6 * (3 - i))) % 64];
        }
        encoded.extend(out.iter().cloned());
    }
    encoded
}

pub fn base64_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
        abcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut decoded = Vec::<u8>::new();
    for quartet in data.chunks(4) {
        let mut indices = [0; 4];
        let mut non_pad_bytes = 4;
        for i in 0..4 {
            let byte = quartet[i];
            if let Some(ix) = table.iter().position(|y| *y == byte) {
                indices[i] = ix as u8;
            } else if byte == 61 {
                non_pad_bytes = min(non_pad_bytes, i);
            } else {
                return Err(format!(
                    "Input contained invalid base64 character {}",
                    char::from(byte)));
            }
        }
        let v = [
            (indices[0] << 2) + (indices[1] >> 4),
            (indices[1] << 4) + (indices[2] >> 2),
            (indices[2] << 6) + (indices[3]     )
        ];
        match non_pad_bytes {
            4 => decoded.extend(&v[..3]),
            3 => decoded.extend(&v[..2]),
            2 => decoded.extend(&v[..1]),
            _ => unreachable!()
        }
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64() {
        fn identity(v: &[u8]) {
            let enc = &base64_encode(v);
            let dec = &base64_decode(enc).unwrap();
            assert_eq!(v[..], dec[..]);
        }
        identity(b"Ringo mogire beam");
        identity(b"Ringo mogire beam!");
        identity(b"Ringo mogire beam!!");
        identity(b"Ringo mogire beam!!!");
    }
}
