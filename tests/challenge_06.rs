use std::fs::File;
use std::io::prelude::*;

use anyhow::Result;

use cryptopals::{find_best_xor_key, Bytes};

#[test]
fn test_hamming_distance() {
    assert_eq!(
        Bytes::from_plaintext("this is a test")
            .hamming_distance(&Bytes::from_plaintext("wokka wokka!!!")),
        37,
    )
}

#[test]
fn test_decrypt_xor() -> Result<()> {
    let mut file = File::open("data/6.txt")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let text = Bytes::from_base64(&contents.lines().collect::<String>())?;
    let key = find_best_xor_key(&text, 2, 40);
    assert_eq!(key.to_plaintext()?, "Terminator X: Bring the noise",);
    assert_eq!(
        (text ^ key).to_plaintext()?.lines().next().unwrap(),
        "I'm back and I'm ringin' the bell ",
    );
    Ok(())
}
