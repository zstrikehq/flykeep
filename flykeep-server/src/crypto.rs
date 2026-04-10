use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

pub fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encryption failed: {e}"))?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<String, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decryption failed: {e}"))?;
    String::from_utf8(plaintext_bytes).map_err(|e| format!("invalid utf-8: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = "my-secret-value";
        let (ciphertext, nonce) = encrypt(&key, plaintext).expect("test: encrypt");
        let result = decrypt(&key, &ciphertext, &nonce).expect("test: decrypt");
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_encrypt_produces_unique_output() {
        let key = test_key();
        let plaintext = "same-value";
        let (ct1, nonce1) = encrypt(&key, plaintext).expect("test: encrypt 1");
        let (ct2, nonce2) = encrypt(&key, plaintext).expect("test: encrypt 2");
        assert_ne!(nonce1, nonce2, "nonces must differ");
        assert_ne!(ct1, ct2, "ciphertexts must differ");
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = test_key();
        let wrong_key = [0xCD; 32];
        let (ciphertext, nonce) = encrypt(&key, "secret").expect("test: encrypt");
        let result = decrypt(&wrong_key, &ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_nonce_fails() {
        let key = test_key();
        let (ciphertext, _nonce) = encrypt(&key, "secret").expect("test: encrypt");
        let wrong_nonce = vec![0u8; 12];
        let result = decrypt(&key, &ciphertext, &wrong_nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_string() {
        let key = test_key();
        let (ciphertext, nonce) = encrypt(&key, "").expect("test: encrypt empty");
        let result = decrypt(&key, &ciphertext, &nonce).expect("test: decrypt empty");
        assert_eq!(result, "");
    }
}
