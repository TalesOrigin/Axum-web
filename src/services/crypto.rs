use anyhow::Context;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const LICENSE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub fn generate_license_key() -> String {
    let mut bytes = [0u8; 25];
    OsRng.fill_bytes(&mut bytes);

    let mut key = String::from("AXUM");
    for group in 0..5 {
        key.push('-');
        for index in 0..5 {
            let byte = bytes[group * 5 + index];
            key.push(LICENSE_ALPHABET[(byte & 31) as usize] as char);
        }
    }

    key
}

pub fn normalize_license_key(input: &str) -> String {
    input
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect::<String>()
}

pub fn license_key_prefix(input: &str) -> String {
    normalize_license_key(input).chars().take(14).collect()
}

pub fn hmac_sha256_hex(secret: &str, value: &str) -> anyhow::Result<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).context("initializing HMAC")?;
    mac.update(value.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub fn hash_license_key(secret: &str, license_key: &str) -> anyhow::Result<String> {
    hmac_sha256_hex(secret, &normalize_license_key(license_key))
}

pub fn hash_device_id(secret: &str, device_id: &str) -> anyhow::Result<String> {
    hmac_sha256_hex(secret, device_id.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn license_keys_are_prefixed_and_normalized() {
        let key = generate_license_key();
        assert!(key.starts_with("AXUM-"));
        assert_eq!(normalize_license_key(&key), normalize_license_key(&key.to_lowercase()));
    }

    #[test]
    fn hmac_is_stable() {
        let a = hash_license_key("secret", "AXUM-ABCDE-FGHIJ").unwrap();
        let b = hash_license_key("secret", "axumabc-defghij").unwrap();
        assert_eq!(a, b);
    }
}
