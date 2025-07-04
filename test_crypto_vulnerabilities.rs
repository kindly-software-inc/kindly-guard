// Test file demonstrating various cryptographic vulnerabilities

use md5;
use sha1::Sha1;
use rand::prelude::*;

// Deprecated hash algorithm (MD5)
fn hash_user_password(password: &str) -> String {
    let digest = md5::compute(password);
    format!("{:x}", digest)
}

// Weak encryption algorithm (DES)
fn encrypt_with_des(data: &[u8], key: &[u8]) -> Vec<u8> {
    let des_cipher = Des::new(key);
    des_cipher.encrypt(data)
}

// Insecure random number generation
fn generate_session_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut rng = thread_rng(); // Not cryptographically secure!
    rng.fill_bytes(&mut key);
    key
}

// Weak RSA key size
const RSA_KEY_SIZE: usize = 1024; // Too small for 2025!

fn generate_weak_rsa() {
    let key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
}

// ECB mode encryption (insecure)
fn encrypt_ecb_mode(key: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).unwrap();
    // ECB mode reveals patterns
    cipher.encrypt_block(data)
}

// Static IV (breaks semantic security)
const IV: [u8; 16] = [0; 16]; // Never do this!

fn encrypt_with_static_iv(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(key, &IV).unwrap();
    cipher.encrypt_vec(plaintext)
}

// Bad password hashing (no salt, simple hash)
fn insecure_password_hash(password: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(password);
    format!("{:x}", hasher.finalize())
}

// Low iteration PBKDF2
fn weak_pbkdf2(password: &[u8], salt: &[u8]) -> [u8; 32] {
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, 1000, &mut output); // Too few iterations!
    output
}

// Hardcoded salt
const SALT: &str = "my_static_salt"; // Security vulnerability!

// Using system time as seed
fn predictable_random() {
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut rng = StdRng::seed_from_u64(seed);
}

// Examples of SECURE implementations for comparison:

use ring::rand::{SecureRandom, SystemRandom};
use argon2::{Argon2, PasswordHasher};

// Secure key generation
fn generate_secure_key() -> Result<[u8; 32], ring::error::Unspecified> {
    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key)?;
    Ok(key)
}

// Secure password hashing
fn hash_password_secure(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

// Using AES-256-GCM (authenticated encryption)
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};

fn encrypt_secure(key: &[u8], plaintext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.encrypt(nonce, plaintext)
}