use rand::prelude::*;
use std::{iter, str};

use anyhow::{anyhow, Result};

// Taken from https://en.wikipedia.org/wiki/Letter_frequency
const LETTERS_BY_FREQ: &[u8] = b" EARIOTNSLCUDPMHGBFYWKVXZJQ";

// TODO This is probably the worst possible implementation...
#[macro_export]
macro_rules! concat_bytes {
    ($x:expr $(,)?) => ({
        let mut z: Vec<u8> = Vec::new();
        z.extend($x);
        z
    });
    ($x:expr, $($y:expr),+ $(,)?) => ({
        let mut z: Vec<u8> = Vec::new();
        z.extend($x);
        z.extend(concat_bytes!($($y),+));
        z
    })
}

pub fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    Ok(hex
        .as_bytes()
        .chunks(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x)?, 16).map_err(|e| e.into()))
        .collect::<Result<Vec<_>>>()?)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn letter_freq_score(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .filter_map(|&x| {
            LETTERS_BY_FREQ
                .iter()
                .position(|y| x.eq_ignore_ascii_case(y))
                .map(|n| LETTERS_BY_FREQ.len() - n)
        })
        .sum()
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    let mut count = 0;
    for byte in xor(a, b) {
        for j in 0..8 {
            count += (byte >> j & 1) as usize;
        }
    }
    count
}

pub fn count_repeating_blocks(bytes: &[u8], blocksize: usize) -> usize {
    let mut count = 0;
    let blocks: Vec<_> = bytes.chunks(blocksize).collect();
    for i in 0..blocks.len() {
        for j in 0..i {
            if blocks[i] == blocks[j] {
                count += 1;
            }
        }
    }
    count
}

pub fn find_best_single_byte_xor_key(bytes: &[u8]) -> u8 {
    (0..256)
        .max_by_key(|&key| letter_freq_score(&xor(bytes, &[key as u8])))
        .unwrap() as u8
}

fn mean(iter: impl Iterator<Item = f64>) -> f64 {
    let mut sum = 0f64;
    let mut count = 0;
    for x in iter {
        sum += x;
        count += 1;
    }
    sum / count as f64
}

fn find_probable_keysize(bytes: &[u8], min: usize, max: usize) -> usize {
    (min..max)
        .min_by_key(|&keysize| {
            // we need an integer key because f64 doesn't implement Ord, so multiply up so we don't
            // lose too much precision in the cast
            (1e6 * mean(
                bytes
                    .chunks(keysize)
                    .collect::<Vec<_>>()
                    .windows(2)
                    .map(|window| match window {
                        [a, b] => hamming_distance(a, b) as f64 / keysize as f64,
                        _ => unreachable!(),
                    }),
            )) as usize
        })
        .unwrap()
}

fn transposed_blocks(bytes: &[u8], blocksize: usize) -> Vec<Vec<u8>> {
    let mut transposed: Vec<Vec<u8>> = iter::repeat(Vec::new()).take(blocksize).collect();
    let mut i = 0;
    for block in bytes.chunks(blocksize) {
        for byte in block.iter() {
            transposed[i].push(*byte);
            i = (i + 1) % transposed.len();
        }
    }
    transposed
}

pub fn find_best_xor_key(bytes: &[u8], min_keysize: usize, max_keysize: usize) -> Vec<u8> {
    transposed_blocks(
        bytes,
        find_probable_keysize(bytes, min_keysize, max_keysize),
    )
    .iter()
    .map(|block| find_best_single_byte_xor_key(block))
    .collect()
}

pub fn pad(bytes: &[u8], size: usize) -> Vec<u8> {
    let short = (size - bytes.len()) as u8;
    let mut padded = bytes.to_vec();
    for _ in 0..short {
        padded.push(short);
    }
    padded
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter()
        .zip(b.iter().cycle())
        .map(|(&x, &y)| x ^ y)
        .collect()
}

fn encrypt_aes_block(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = openssl::symm::Cipher::aes_128_ecb();
    let mut encrypter =
        openssl::symm::Crypter::new(cipher, openssl::symm::Mode::Encrypt, key, None)?;
    encrypter.pad(false);
    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let mut count = encrypter.update(plaintext, &mut ciphertext)?;
    count += encrypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count);
    Ok(ciphertext)
}

fn decrypt_aes_block(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = openssl::symm::Cipher::aes_128_ecb();
    let mut decrypter =
        openssl::symm::Crypter::new(cipher, openssl::symm::Mode::Decrypt, key, None)?;
    decrypter.pad(false);
    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = decrypter.update(ciphertext, &mut plaintext)?;
    count += decrypter.finalize(&mut plaintext[count..])?;
    plaintext.truncate(count);
    Ok(plaintext)
}

pub fn encrypt_aes_ecb(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut ciphertext = Vec::new();
    let padded = pad(plaintext, plaintext.len() + 16 - plaintext.len() % 16);
    for block in padded.chunks(16) {
        ciphertext.extend(encrypt_aes_block(&block, key)?);
    }
    Ok(ciphertext)
}

pub fn decrypt_aes_ecb(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut plaintext = Vec::new();
    for block in ciphertext.chunks(16) {
        plaintext.extend(decrypt_aes_block(&block, key)?);
    }
    plaintext.truncate(plaintext.len() - *plaintext.last().unwrap() as usize);
    Ok(plaintext)
}

pub fn encrypt_aes_cbc(plaintext: &[u8], key: &[u8], ic: &[u8]) -> Result<Vec<u8>> {
    let mut ciphertext = Vec::new();
    let mut last = ic.to_vec();
    let padded = pad(plaintext, plaintext.len() + 16 - plaintext.len() % 16);
    for block in padded.chunks(16) {
        last = encrypt_aes_block(&xor(&last, &block), key)?;
        ciphertext.extend(&last);
    }
    Ok(ciphertext)
}

pub fn decrypt_aes_cbc(ciphertext: &[u8], key: &[u8], ic: &[u8]) -> Result<Vec<u8>> {
    let mut plaintext = Vec::new();
    let mut last = ic;
    for block in ciphertext.chunks(16) {
        plaintext.extend(xor(&decrypt_aes_block(&block, key)?, &last));
        last = block;
    }
    plaintext.truncate(plaintext.len() - *plaintext.last().unwrap() as usize);
    Ok(plaintext)
}

pub fn random_bytes<R: Rng + ?Sized>(n: usize, rng: &mut R) -> Vec<u8> {
    let mut bytes = vec![0; n];
    for byte in bytes.iter_mut() {
        *byte = rng.gen();
    }
    bytes
}

pub fn encode_form_urlencoded(pairs: &[(String, String)]) -> Result<String> {
    Ok(pairs
        .iter()
        .map(|(k, v)| {
            if k.contains("=") || k.contains("&") {
                Err(anyhow!("invalid key {}", k))
            } else if v.contains("=") || v.contains("&") {
                Err(anyhow!("invalid value {}", v))
            } else {
                Ok(format!("{}={}", k, v))
            }
        })
        .collect::<Result<Vec<_>>>()?
        .join("&"))
}

pub fn decode_form_urlencoded(s: &str) -> Result<Vec<(String, String)>> {
    s.split("&")
        .map(|pair| {
            let kv: Vec<_> = pair.split("=").collect();
            match kv.len() {
                2 => Ok((kv[0].to_string(), kv[1].to_string())),
                _ => Err(anyhow!("malformed pair {}", pair)),
            }
        })
        .collect()
}
