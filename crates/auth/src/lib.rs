use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_number: bool,
    pub require_symbol: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_number: true,
            require_symbol: true,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswordPolicyError {
    #[error("password is shorter than the required minimum length")]
    TooShort,
    #[error("password must include at least one number")]
    MissingNumber,
    #[error("password must include at least one symbol")]
    MissingSymbol,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("password hashing failed")]
    PasswordHash,
    #[error("password verification failed")]
    PasswordVerify,
    #[error("session token operation failed")]
    SessionToken,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionClaims {
    pub sub: String,
    pub jti: String,
    pub exp: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSessionToken {
    pub user_id: Uuid,
    pub session_id: Uuid,
}

pub fn validate_password_policy(
    password: &str,
    policy: &PasswordPolicy,
) -> Result<(), PasswordPolicyError> {
    if password.chars().count() < policy.min_length {
        return Err(PasswordPolicyError::TooShort);
    }

    if policy.require_number && !password.chars().any(|character| character.is_ascii_digit()) {
        return Err(PasswordPolicyError::MissingNumber);
    }

    if policy.require_symbol
        && !password
            .chars()
            .any(|character| !character.is_ascii_alphanumeric())
    {
        return Err(PasswordPolicyError::MissingSymbol);
    }

    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AuthError::PasswordHash)
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, AuthError> {
    let parsed_hash = PasswordHash::new(password_hash).map_err(|_| AuthError::PasswordVerify)?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn issue_session_token(
    user_id: Uuid,
    session_id: Uuid,
    secret: &[u8],
    ttl_seconds: i64,
) -> Result<String, AuthError> {
    let expires_at = Utc::now() + Duration::seconds(ttl_seconds);
    let claims = SessionClaims {
        sub: user_id.to_string(),
        jti: session_id.to_string(),
        exp: expires_at.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|_| AuthError::SessionToken)
}

pub fn verify_session_token(token: &str, secret: &[u8]) -> Result<VerifiedSessionToken, AuthError> {
    let token_data = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::default(),
    )
    .map_err(|_| AuthError::SessionToken)?;

    Ok(VerifiedSessionToken {
        user_id: Uuid::parse_str(&token_data.claims.sub).map_err(|_| AuthError::SessionToken)?,
        session_id: Uuid::parse_str(&token_data.claims.jti).map_err(|_| AuthError::SessionToken)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_password_that_matches_policy() {
        assert!(validate_password_policy("correct-horse-7", &PasswordPolicy::default()).is_ok());
    }

    #[test]
    fn rejects_short_password() {
        assert_eq!(
            validate_password_policy("short", &PasswordPolicy::default()).unwrap_err(),
            PasswordPolicyError::TooShort
        );
    }

    #[test]
    fn hashes_and_verifies_password() {
        let password_hash = hash_password("correct-horse-7!").unwrap();

        assert!(verify_password("correct-horse-7!", &password_hash).unwrap());
        assert!(!verify_password("wrong-password", &password_hash).unwrap());
    }

    #[test]
    fn issues_and_verifies_session_token() {
        let user_id = Uuid::now_v7();
        let session_id = Uuid::now_v7();
        let token = issue_session_token(user_id, session_id, b"test-secret", 3600).unwrap();
        let verified = verify_session_token(&token, b"test-secret").unwrap();

        assert_eq!(verified.user_id, user_id);
        assert_eq!(verified.session_id, session_id);
    }
}
