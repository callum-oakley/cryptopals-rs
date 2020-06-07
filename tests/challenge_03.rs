use anyhow::Result;

use cryptopals::{decrypt_single_byte_xor, Bytes};

#[test]
fn test_decrypt_single_byte_xor() -> Result<()> {
    assert_eq!(
        decrypt_single_byte_xor(&Bytes::from_hex(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        )?)
        .to_plaintext()?,
        "Cooking MC's like a pound of bacon",
    );
    Ok(())
}
