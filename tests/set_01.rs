use std::fs::File;
use std::io::prelude::*;

use anyhow::Result;

use cryptopals::*;

#[test]
fn challenge_01() -> Result<()> {
    const HEX: &str = concat!(
        "49276d206b696c6c696e6720796f757220627261696e206c",
        "696b65206120706f69736f6e6f7573206d757368726f6f6d",
    );
    const BASE64: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(Bytes::from_hex(HEX)?.to_base64(), BASE64);
    Ok(())
}

#[test]
fn challenge_02() -> Result<()> {
    assert_eq!(
        (Bytes::from_hex("1c0111001f010100061a024b53535009181c")?
            ^ Bytes::from_hex("686974207468652062756c6c277320657965")?)
        .to_hex(),
        "746865206b696420646f6e277420706c6179",
    );
    Ok(())
}

#[test]
fn challenge_03() -> Result<()> {
    let text =
        Bytes::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
    assert_eq!(
        (&text ^ &vec![text.find_best_single_byte_xor_key()].into()).to_plaintext()?,
        "Cooking MC's like a pound of bacon",
    );
    Ok(())
}

#[test]
fn challenge_04() -> Result<()> {
    let mut file = File::open("data/4.txt")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let text = contents
        .lines()
        .map(|line| Bytes::from_hex(line))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .flat_map(|text| (0..256).map(move |key| text ^ &vec![key as u8].into()))
        .max_by_key(|p| p.letter_freq_score())
        .unwrap();

    assert_eq!(text.to_plaintext()?, "Now that the party is jumping\n");
    Ok(())
}

#[test]
fn challenge_05() {
    assert_eq!(
        (Bytes::from_plaintext(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        ) ^ Bytes::from_plaintext("ICE"))
        .to_hex(),
        concat!(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272",
            "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        ),
    )
}

#[test]
fn challenge_06() -> Result<()> {
    assert_eq!(
        Bytes::from_plaintext("this is a test")
            .hamming_distance(&Bytes::from_plaintext("wokka wokka!!!")),
        37,
    );

    let mut file = File::open("data/6.txt")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let text = Bytes::from_base64(&contents.lines().collect::<String>())?;
    let key = text.find_best_xor_key(2, 40);
    assert_eq!(key.to_plaintext()?, "Terminator X: Bring the noise",);
    assert_eq!(
        (text ^ key).to_plaintext()?.lines().next().unwrap(),
        "I'm back and I'm ringin' the bell ",
    );
    Ok(())
}

#[test]
fn challenge_07() -> Result<()> {
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

#[test]
fn challenge_08() -> Result<()> {
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
