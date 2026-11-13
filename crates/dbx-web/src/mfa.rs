use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;

pub const STEP_SECONDS: i64 = 30;
pub const DIGITS: u32 = 6;
const WINDOW: i64 = 1;
const SECRET_BYTES: usize = 20;
pub const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
pub const ISSUER: &str = "DBX";

pub fn generate_secret() -> Result<String, String> {
    let mut bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
    Ok(BASE32_NOPAD.encode(&bytes))
}

fn decode_secret(secret: &str) -> Option<Vec<u8>> {
    let normalized: String =
        secret.chars().filter(|ch| !ch.is_whitespace() && *ch != '=').map(|ch| ch.to_ascii_uppercase()).collect();
    BASE32_NOPAD.decode(normalized.as_bytes()).ok()
}

pub fn code_at(secret: &[u8], step: i64) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&(step.max(0) as u64).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    binary % 10u32.pow(DIGITS)
}

pub fn step_at(now_millis: i64) -> i64 {
    now_millis.div_euclid(1000) / STEP_SECONDS
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

pub fn verify(secret: &str, code: &str, now_millis: i64) -> Option<i64> {
    let code: String = code.chars().filter(|ch| !ch.is_whitespace()).collect();
    if code.len() != DIGITS as usize || !code.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let key = decode_secret(secret)?;
    let current = step_at(now_millis);
    let mut matched = None;
    for step in current - WINDOW..=current + WINDOW {
        let expected = format!("{:0width$}", code_at(&key, step), width = DIGITS as usize);
        if constant_time_eq(expected.as_bytes(), code.as_bytes()) && matched.is_none() {
            matched = Some(step);
        }
    }
    matched
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (byte as char).to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

pub fn otpauth_uri(username: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}",
        issuer = ISSUER,
        label = percent_encode(username),
    )
}

pub fn generate_recovery_codes() -> Result<Vec<String>, String> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let mut bytes = [0u8; 10];
            getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
            let chars: String = bytes
                .iter()
                .map(|byte| RECOVERY_ALPHABET[usize::from(*byte) % RECOVERY_ALPHABET.len()] as char)
                .collect();
            Ok(format!("{}-{}", &chars[..5], &chars[5..]))
        })
        .collect()
}

pub fn normalize_recovery_code(code: &str) -> String {
    let compact: String =
        code.chars().filter(|ch| ch.is_ascii_alphanumeric()).map(|ch| ch.to_ascii_lowercase()).collect();
    if compact.len() == 10 {
        format!("{}-{}", &compact[..5], &compact[5..])
    } else {
        compact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn matches_the_rfc_6238_sha1_test_vectors() {
        for (seconds, expected) in
            [(59, 287_082), (1_111_111_109, 81_804), (1_234_567_890, 5_924), (2_000_000_000, 279_037)]
        {
            assert_eq!(code_at(RFC_SECRET, seconds / STEP_SECONDS), expected, "{seconds}");
        }
    }

    #[test]
    fn verifies_codes_inside_the_window_only() {
        let secret = BASE32_NOPAD.encode(RFC_SECRET);
        let now = 1_111_111_109_000;
        let step = step_at(now);
        let code = |step: i64| format!("{:06}", code_at(RFC_SECRET, step));
        assert_eq!(verify(&secret, &code(step), now), Some(step));
        assert_eq!(verify(&secret, &code(step - 1), now), Some(step - 1));
        assert_eq!(verify(&secret, &code(step + 1), now), Some(step + 1));
        assert_eq!(verify(&secret, &code(step + 2), now), None);
        assert_eq!(verify(&secret, "081 804", now), Some(step));
        assert_eq!(verify(&secret, "12345", now), None);
        assert_eq!(verify(&secret, "abcdef", now), None);
        assert_eq!(verify(&secret.to_lowercase(), &code(step), now), Some(step));
    }

    #[test]
    fn builds_secrets_uris_and_recovery_codes() {
        let secret = generate_secret().unwrap();
        assert_eq!(decode_secret(&secret).unwrap().len(), SECRET_BYTES);
        assert_ne!(secret, generate_secret().unwrap());
        assert_eq!(
            otpauth_uri("ana maria@corp", "ABC"),
            "otpauth://totp/DBX:ana%20maria%40corp?secret=ABC&issuer=DBX&algorithm=SHA1&digits=6&period=30"
        );
        let codes = generate_recovery_codes().unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        assert!(codes.iter().all(|code| code.len() == 11 && code.as_bytes()[5] == b'-'));
        assert_eq!(normalize_recovery_code(" ABCDE fghjk "), "abcde-fghjk");
    }
}
