use anyhow::Result;

use cryptopals::Bytes;

#[test]
fn test_xor() -> Result<()> {
    assert_eq!(
        (Bytes::from_hex("1c0111001f010100061a024b53535009181c")?
            ^ Bytes::from_hex("686974207468652062756c6c277320657965")?)
        .to_hex(),
        "746865206b696420646f6e277420706c6179",
    );
    Ok(())
}
