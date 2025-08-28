use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params};
use anyhow::Result;
use rand::RngCore;

// Argon2 parameters for better security
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MB
const ARGON2_TIME_COST: u32 = 3;       // 3 iterations
const ARGON2_PARALLELISM: u32 = 1;     // Single thread

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    // Use custom Argon2 parameters for better security
    let params = Params::new(ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, Some(32))
        .map_err(|e| anyhow::anyhow!("Failed to create Argon2 params: {}", e))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let mut output_key = [0u8; 32];

    // Use Argon2id with custom parameters
    argon2.hash_password_into(
        password.as_bytes(),
        salt,
        &mut output_key,
    ).map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

    Ok(output_key)
}

pub fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Invalid key length: {}", e))?;

    // Generate a random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_data(encrypted_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if encrypted_data.len() < 12 {
        anyhow::bail!("Invalid encrypted data: too short");
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Invalid key length: {}", e))?;

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the data
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    Ok(plaintext)
}


// Generate salt for individual entries
pub fn generate_entry_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

// Generate a cryptographically secure random password
pub fn generate_secure_password(length: usize) -> String {


    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789\
                             !@#$%^&*()_+-=[]{}|;:,.<>?";

    let mut password = Vec::with_capacity(length);
    let mut rng = OsRng;

    for _ in 0..length {
        let idx = (rng.next_u32() as usize) % CHARSET.len();
        password.push(CHARSET[idx]);
    }

    String::from_utf8(password).unwrap()
}

// Encrypt data using password and salt (for per-entry encryption)
pub fn encrypt_data_with_password(data: &[u8], password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key(password, salt)?;
    encrypt_data(data, &key)
}

// Decrypt data using password and salt (for per-entry decryption)
pub fn decrypt_data_with_password(encrypted_data: &[u8], password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key(password, salt)?;
    decrypt_data(encrypted_data, &key)
}

// Secure memory clearing (best effort)
pub fn clear_sensitive_data(data: &mut [u8]) {
    use std::sync::atomic::{compiler_fence, Ordering};
    use std::ptr::write_volatile;

    for byte in data.iter_mut() {
        unsafe {
            write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}
