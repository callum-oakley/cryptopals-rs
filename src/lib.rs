use core::ops;
use std::{iter, str};

use anyhow::Result;
use openssl::symm::{decrypt, Cipher};

// Taken from https://en.wikipedia.org/wiki/Letter_frequency
const LETTERS_BY_FREQ: &[u8] = b" EARIOTNSLCUDPMHGBFYWKVXZJQ";

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn new() -> Self {
        Bytes(Vec::new())
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Bytes(
            hex.as_bytes()
                .chunks(2)
                .map(|x| u8::from_str_radix(std::str::from_utf8(x)?, 16).map_err(|e| e.into()))
                .collect::<Result<Vec<_>>>()?,
        ))
    }

    pub fn from_base64(b64: &str) -> Result<Self> {
        Ok(Bytes(base64::decode(b64)?))
    }

    pub fn from_plaintext(plaintext: &str) -> Self {
        Bytes(plaintext.as_bytes().into())
    }

    pub fn to_hex(&self) -> String {
        self.iter().map(|x| format!("{:02x}", x)).collect()
    }

    pub fn to_base64(&self) -> String {
        base64::encode(self)
    }

    pub fn to_plaintext(&self) -> Result<&str> {
        Ok(str::from_utf8(&self.0)?)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn push(&mut self, byte: u8) {
        self.0.push(byte)
    }

    pub fn iter(&self) -> std::slice::Iter<u8> {
        self.0.iter()
    }

    pub fn letter_freq_score(&self) -> usize {
        self.iter()
            .filter_map(|&x| {
                LETTERS_BY_FREQ
                    .iter()
                    .position(|y| x.eq_ignore_ascii_case(y))
                    .map(|n| LETTERS_BY_FREQ.len() - n)
            })
            .sum()
    }

    pub fn hamming_distance(&self, other: &Self) -> usize {
        let mut count = 0;
        for byte in self ^ other {
            for j in 0..8 {
                count += (byte >> j & 1) as usize;
            }
        }
        count
    }

    pub fn blocks(&self, block_size: usize) -> Blocks {
        self.0.chunks(block_size).map(|c| c.into()).collect()
    }

    pub fn decrypt_aes_ecb(&self, key: &Bytes) -> Result<Self> {
        Ok(decrypt(Cipher::aes_128_ecb(), key.as_ref(), None, self.as_ref())?.into())
    }

    pub fn count_repeating_blocks(&self, blocksize: usize) -> usize {
        let mut count = 0;
        let blocks = self.blocks(blocksize);
        for i in 0..blocks.len() {
            for j in 0..i {
                if blocks[i] == blocks[j] {
                    count += 1;
                }
            }
        }
        count
    }

    pub fn find_best_single_byte_xor_key(&self) -> u8 {
        (0..256)
            .max_by_key(|&key| (self ^ &vec![key as u8].into()).letter_freq_score())
            .unwrap() as u8
    }

    fn find_probable_keysize(&self, min: usize, max: usize) -> usize {
        (min..max)
            .min_by_key(|&keysize| {
                // we need an integer key because f64 doesn't implement Ord, so multiply up so we don't
                // lose too much precision in the cast
                (1e6 * mean(self.blocks(keysize).windows(2).map(|window| match window {
                    [a, b] => a.hamming_distance(b) as f64 / keysize as f64,
                    _ => unreachable!(),
                }))) as usize
            })
            .unwrap()
    }

    pub fn find_best_xor_key(&self, min_keysize: usize, max_keysize: usize) -> Bytes {
        self.blocks(self.find_probable_keysize(min_keysize, max_keysize))
            .transpose()
            .iter()
            .map(|block| block.find_best_single_byte_xor_key())
            .collect()
    }
}

impl<T: Into<Vec<u8>>> From<T> for Bytes {
    fn from(x: T) -> Self {
        Bytes(x.into())
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl IntoIterator for Bytes {
    type Item = u8;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl iter::FromIterator<u8> for Bytes {
    fn from_iter<I: IntoIterator<Item = u8>>(iter: I) -> Self {
        let mut bytes = Bytes::new();
        for byte in iter {
            bytes.push(byte)
        }
        bytes
    }
}

impl ops::BitXor for &Bytes {
    type Output = Bytes;

    fn bitxor(self, other: &Bytes) -> Self::Output {
        Bytes(
            self.iter()
                .zip(other.iter().cycle())
                .map(|(&x, &y)| x ^ y)
                .collect(),
        )
    }
}

impl ops::BitXor for Bytes {
    type Output = Bytes;

    fn bitxor(self, other: Bytes) -> Self::Output {
        &self ^ &other
    }
}

impl ops::Index<usize> for Bytes {
    type Output = u8;

    fn index(&self, i: usize) -> &Self::Output {
        self.0.index(i)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Blocks(Vec<Bytes>);

impl Blocks {
    pub fn new() -> Self {
        Blocks(Vec::new())
    }

    pub fn push(&mut self, block: Bytes) {
        self.0.push(block)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn windows(&self, size: usize) -> impl Iterator<Item = &[Bytes]> {
        self.0.windows(size)
    }

    pub fn keysize(&self) -> usize {
        self.0[0].len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Bytes> {
        self.0.iter()
    }

    pub fn transpose(&self) -> Self {
        let mut transposed: Blocks = iter::repeat(Bytes::new()).take(self.keysize()).collect();
        let mut i = 0;
        for block in self.iter() {
            for byte in block.iter() {
                transposed[i].push(*byte);
                i = (i + 1) % transposed.len();
            }
        }
        transposed
    }
}

impl ops::Index<usize> for Blocks {
    type Output = Bytes;

    fn index(&self, i: usize) -> &Self::Output {
        &self.0[i]
    }
}

impl ops::IndexMut<usize> for Blocks {
    fn index_mut(&mut self, i: usize) -> &mut Self::Output {
        &mut self.0[i]
    }
}

impl IntoIterator for Blocks {
    type Item = Bytes;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl iter::FromIterator<Bytes> for Blocks {
    fn from_iter<I: IntoIterator<Item = Bytes>>(iter: I) -> Self {
        let mut blocks = Blocks::new();
        for block in iter {
            blocks.push(block)
        }
        blocks
    }
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
