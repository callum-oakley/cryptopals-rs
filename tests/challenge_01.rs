use anyhow::Result;

use cryptopals::Bytes;

const HEX: &str = concat!(
    "49276d206b696c6c696e6720796f757220627261696e206c",
    "696b65206120706f69736f6e6f7573206d757368726f6f6d",
);
const BASE64: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

#[test]
fn convert_hex_to_base64() -> Result<()> {
    assert_eq!(Bytes::from_hex(HEX)?.to_base64(), BASE64);
    Ok(())
}

#[test]
fn hex_round_trip() -> Result<()> {
    assert_eq!(Bytes::from_hex(HEX)?.to_hex(), HEX);
    Ok(())
}
