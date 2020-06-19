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
        let (ciphertext, mode) = encryption_oracle(&vec![0; 64])?;
        let blocks: Vec<_> = ciphertext.chunks(16).collect();
        assert_eq!(blocks[1] == blocks[2], mode == Mode::ECB);
    }
    Ok(())
}
