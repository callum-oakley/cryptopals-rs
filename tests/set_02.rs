use rand::prelude::*;
use std::collections::HashMap;
use std::str;

use anyhow::Result;

use cryptopals::*;

#[test]
fn challenge_09() -> Result<()> {
    assert_eq!(
        str::from_utf8(&pad(b"YELLOW SUBMARINE", 20))?,
        "YELLOW SUBMARINE\x04\x04\x04\x04"
    );
    Ok(())
}

#[test]
fn challenge_10() -> Result<()> {
    let ciphertext = base64::decode(include_str!("data/10.txt").lines().collect::<String>())?;
    let key = b"YELLOW SUBMARINE";
    let plaintext = decrypt_aes_cbc(&ciphertext, key, &[0; 16])?;
    assert_eq!(
        str::from_utf8(&plaintext)?,
        include_str!("data/sample_plaintext.txt")
    );

    assert_eq!(
        decrypt_aes_cbc(
            &encrypt_aes_cbc(b"hello world", key, &[0; 16])?,
            key,
            &[0; 16]
        )?,
        b"hello world",
    );
    Ok(())
}

#[test]
fn challenge_11() -> Result<()> {
    for _ in 0..100 {
        // We can determine whether our oracle is using ECB or CBC by
        // 1. providing enough plaintext of uniform 0s to ensure we've got at least 4 blocks after
        //    padding
        // 2. then the middle two blocks of plaintext are all 0, (and crucially, the same as one
        //    another)
        // 3. then ECB will encode them to the same ciphertext, but CBC will not (in general).
        let (ciphertext, mode) = encryption_oracle(&[0; 64])?;
        let blocks: Vec<_> = ciphertext.chunks(16).collect();
        assert_eq!(blocks[1] == blocks[2], mode == Mode::ECB);
    }
    Ok(())
}

#[test]
fn challenge_12() -> Result<()> {
    let mut rng = thread_rng();

    // unknown and key are "secret", pretend we don't have access to them
    let unknown = base64::decode(concat!(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg",
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq",
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg",
        "YnkK",
    ))?;
    let key = random_bytes(16, &mut rng);

    let oracle = |input: &[u8]| encrypt_aes_ecb(&concat_bytes!(input, &unknown), &key);

    // Append bytes to the plaintext one at a time until the ciphertext gets one block longer.
    let mut block_size = 0;
    let start_length = oracle(&[0; 0])?.len();
    for n in 1.. {
        let ciphertext = oracle(&vec![0; n])?;
        if ciphertext.len() > start_length {
            block_size = ciphertext.len() - start_length;
            break;
        }
    }
    assert_eq!(block_size, 16);

    // If the oracle is using ECB, we should be able to pass it two identical blocks of plaintext,
    // and get out two identical blocks of ciphertext. Let's test that hypothesis a few times.
    for _ in 0..100 {
        let test_bytes = random_bytes(block_size, &mut rng);
        let ciphertext = oracle(&concat_bytes!(&test_bytes, &test_bytes))?;
        let mut blocks = ciphertext.chunks(block_size);
        assert_eq!(blocks.next(), blocks.next());
    }

    let pad_length = oracle(&[0; 0])?.len();
    let mut plaintext = Vec::new();
    for _ in 0..pad_length {
        let mut ciphertext_map = HashMap::new();
        let pad = concat_bytes!(&vec![0; pad_length - plaintext.len() - 1], &plaintext);
        for x in 0..=255 {
            let mut ciphertext = oracle(&concat_bytes!(&pad, &[x]))?;
            ciphertext.truncate(pad_length);
            ciphertext_map.insert(ciphertext, x);
        }
        let mut ciphertext = oracle(&vec![0; pad_length - plaintext.len() - 1])?;
        ciphertext.truncate(pad_length);
        match ciphertext_map.get(&ciphertext) {
            Some(x) => plaintext.push(*x),
            None => {
                break;
            }
        };
    }
    plaintext.truncate(unknown.len()); // We get one extra character from padding.
    assert_eq!(plaintext, unknown);
    Ok(())
}
