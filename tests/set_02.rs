use std::fs::File;
use std::io::prelude::*;
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
    let mut file = File::open("data/10.txt")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let ciphertext = base64::decode(&contents.lines().collect::<String>())?;
    let key = b"YELLOW SUBMARINE";
    let plaintext = decrypt_aes_cbc(&ciphertext, key, &[0; 16])?;
    assert_eq!(
        str::from_utf8(&plaintext)?.lines().next().unwrap(),
        "I'm back and I'm ringin' the bell "
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
