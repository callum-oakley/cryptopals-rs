use std::fs::File;
use std::io::prelude::*;

use anyhow::Result;

use cryptopals::Bytes;

#[test]
fn detect_aes_in_ecb_mode() -> Result<()> {
    let mut file = File::open("data/8.txt")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let texts: Vec<Bytes> = contents
        .lines()
        .map(|line| Bytes::from_hex(line))
        .collect::<Result<_>>()?;

    let ecb_text = texts
        .iter()
        .max_by_key(|text| {
            (2..40)
                .map(|blocksize| text.count_repeating_blocks(blocksize))
                .sum::<usize>()
        })
        .unwrap();

    assert_eq!(
        ecb_text.to_hex(),
        concat!(
            "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf",
            "9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a",
            "08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4f",
            "d5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a",
        ),
    );
    Ok(())
}
