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
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

pub fn base64_decode(data: &[u8]) -> Vec<u8> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut decoded = Vec::<u8>::new();
    for quartet in data.chunks(4) {
        let indices: Vec<u8> = quartet
            .iter()
            .map(|x| table.iter().position(|y| y == x))
            .filter_map(|x| x)
            .map(|x| x as u8)
            .collect();

        // Convert the four 6-bit indices into three bytes,
        // fewer if there were any `=`s
        let v =
            [(*indices.get(0).unwrap_or(&0) << 2) + (*indices.get(1).unwrap_or(&0) >> 4)
            ,(*indices.get(1).unwrap_or(&0) << 4) + (*indices.get(2).unwrap_or(&0) >> 2)
            ,(*indices.get(2).unwrap_or(&0) << 6) + (*indices.get(3).unwrap_or(&0))
            ];

        decoded.extend(&v[..indices.len() - 1]);
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64() {
        fn identity(v: &[u8]) {
            let enc = &base64_encode(v);
            let dec = &base64_decode(enc);
            assert_eq!(v[..], dec[..]);
        }
        identity(b"Ringo mogire beam");
        identity(b"Ringo mogire beam!");
        identity(b"Ringo mogire beam!!");
    }
}
