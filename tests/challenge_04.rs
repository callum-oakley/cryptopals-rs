use anyhow::Result;

use cryptopals::find_and_decrypt_single_byte_xor;

#[test]
fn test_find_and_decrypt_single_byte_xor() -> Result<()> {
    assert_eq!(
        find_and_decrypt_single_byte_xor("data/4.txt")?.to_plaintext()?,
        "Now that the party is jumping\n",
    );
    Ok(())
}
