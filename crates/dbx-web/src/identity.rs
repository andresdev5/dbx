use std::sync::OnceLock;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

pub const MIN_PASSWORD_CHARS: usize = 8;
pub const MAX_PASSWORD_BYTES: usize = 1024;
pub const MAX_USERNAME_CHARS: usize = 64;

pub const PASSWORD_TOO_SHORT: &str = "password_too_short";
pub const PASSWORD_TOO_LONG: &str = "password_too_long";
pub const USERNAME_INVALID: &str = "username_invalid";

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt).map(|hash| hash.to_string()).map_err(|e| e.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    PasswordHash::new(hash).is_ok_and(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

pub fn burn_verification(password: &str) {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let hash = DUMMY.get_or_init(|| hash_password("dbx-timing-equalizer").unwrap_or_default());
    let _ = verify_password(password, hash);
}

pub fn check_new_password(password: &str) -> Result<(), &'static str> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(PASSWORD_TOO_LONG);
    }
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(PASSWORD_TOO_SHORT);
    }
    Ok(())
}

pub fn normalize_username(input: &str) -> Result<String, &'static str> {
    let username = input.trim();
    let length = username.chars().count();
    let valid_chars = username.chars().all(|ch| ch.is_alphanumeric() || matches!(ch, '.' | '_' | '-' | '@'));
    if length == 0 || length > MAX_USERNAME_CHARS || !valid_chars {
        return Err(USERNAME_INVALID);
    }
    Ok(username.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_verify_only_the_original_password() {
        let hash = hash_password("correct horse").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("correct horse", &hash));
        assert!(!verify_password("correct horsE", &hash));
        assert!(!verify_password("correct horse", "not-a-hash"));
    }

    #[test]
    fn oversized_passwords_are_rejected_before_hashing() {
        let long = "x".repeat(MAX_PASSWORD_BYTES + 1);
        assert_eq!(check_new_password(&long), Err(PASSWORD_TOO_LONG));
        assert!(!verify_password(&long, &hash_password("short-but-valid").unwrap()));
    }

    #[test]
    fn new_passwords_need_eight_characters() {
        assert_eq!(check_new_password("1234567"), Err(PASSWORD_TOO_SHORT));
        assert_eq!(check_new_password("contraseña"), Ok(()));
        assert_eq!(check_new_password("ñññññññ"), Err(PASSWORD_TOO_SHORT));
    }

    #[test]
    fn usernames_are_trimmed_and_restricted() {
        assert_eq!(normalize_username("  ana.pérez@corp  "), Ok("ana.pérez@corp".to_string()));
        assert_eq!(normalize_username(""), Err(USERNAME_INVALID));
        assert_eq!(normalize_username("ana perez"), Err(USERNAME_INVALID));
        assert_eq!(normalize_username("ana;drop"), Err(USERNAME_INVALID));
        assert_eq!(normalize_username(&"a".repeat(65)), Err(USERNAME_INVALID));
    }
}
