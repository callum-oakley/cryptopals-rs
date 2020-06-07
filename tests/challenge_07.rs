use std::fs::File;
use std::io::prelude::*;

use anyhow::Result;

use cryptopals::Bytes;

#[test]
fn aes_in_ecb_mode() -> Result<()> {
    let mut file = File::open("data/7.txt")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let text = Bytes::from_base64(&contents.lines().collect::<String>())?;

    assert_eq!(
        text.decrypt_aes_ecb(&Bytes::from_plaintext("YELLOW SUBMARINE"))?
            .to_plaintext()?
            .lines()
            .next()
            .unwrap(),
        "I'm back and I'm ringin' the bell ",
    );
    Ok(())
}
