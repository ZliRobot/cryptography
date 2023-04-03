use std::fmt::Write;

// https://www.rfc-editor.org/rfc/rfc4634.txt
static K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn padded(message: &[u8]) -> Vec<u8> {
    let l = message.len();
    let len_without_zeros = l * 8 + 8 + 64;
    let no_of_zeros = (512 - len_without_zeros % 512) % 512;

    let mut message = message.to_vec();
    message.push(0b10000000);
    message.append(&mut vec![0u8; no_of_zeros / 8]);
    message.append(&mut ((l * 8) as u64).to_be_bytes().to_vec());

    message
}

pub fn sha_2(message: &[u8]) -> Vec<u8> {
    let message = padded(message);

    let ch = |x:u32, y:u32, z:u32| (x & y) ^ (!x & z);
    let maj = |x:u32, y:u32, z:u32| (x & y) ^ (x & z) ^ (y & z);
    let bsig0 = |x:u32| x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22);
    let bsig1 = |x:u32| x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25);
    let ssig0 = |x:u32| x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
    let ssig1 = |x:u32| x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10);

    let mut h0: u32 = 0x6a09e667;
    let mut h1: u32 = 0xbb67ae85;
    let mut h2: u32 = 0x3c6ef372;
    let mut h3: u32 = 0xa54ff53a;
    let mut h4: u32 = 0x510e527f;
    let mut h5: u32 = 0x9b05688c;
    let mut h6: u32 = 0x1f83d9ab;
    let mut h7: u32 = 0x5be0cd19;

    for chunk in message.chunks(64) {
        // Schedule array
        let mut w = vec![0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }

        for i in 16..64 {
            w[i] = w[i - 16]
                .wrapping_add(ssig0(w[i - 15]))
                .wrapping_add(w[i - 7])
                .wrapping_add(ssig1(w[i - 2]));
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        let mut temp1: u32;
        let mut temp2: u32;
        for i in 0..64 {
            temp1 = h
                .wrapping_add(bsig1(e))
                .wrapping_add(ch(e,f,g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            temp2 = bsig0(a).wrapping_add(maj(a,b,c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    let mut hash = h0.to_be_bytes().to_vec();
    hash.append(&mut h1.to_be_bytes().to_vec());
    hash.append(&mut h2.to_be_bytes().to_vec());
    hash.append(&mut h3.to_be_bytes().to_vec());
    hash.append(&mut h4.to_be_bytes().to_vec());
    hash.append(&mut h5.to_be_bytes().to_vec());
    hash.append(&mut h6.to_be_bytes().to_vec());
    hash.append(&mut h7.to_be_bytes().to_vec());
    hash
}

pub fn u8_to_hex_string(input: &[u8]) -> String {
    let mut result = String::new();
    for i in input {
        write!(result, "{:02x}", i).unwrap();
    }
    result
}

#[cfg(test)]
use sha256::digest;
#[test]
fn test_padded_length() {
    let message = padded(&[0]);
    dbg!(&message);
    assert!(message.len() == 64);
}

#[test]
fn test_padded_content() {
    let message = [0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101];

    let expected = "61626364658000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028".to_string();
    let result = u8_to_hex_string(&padded(&message));
    assert_eq!(expected, result);
}

#[test]
fn test_sha_2_256_empty() {
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let result = u8_to_hex_string(&sha_2("".as_bytes()));

    assert_eq!(expected, result);
}

#[test]
fn test_sha_2_256_zero() {
    let expected = "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9";
    let result = u8_to_hex_string(&sha_2("0".as_bytes()));

    assert_eq!(expected, result);
}

#[test]
fn test_sha_2_256_brown_fox() {
    let message = "The quick brown fox jumps over the lazy dog.";
    let expected = digest(message);
    let result = u8_to_hex_string(&sha_2(message.as_bytes()));

    assert_eq!(expected, result);
}
