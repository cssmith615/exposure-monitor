use serde::{Deserialize, Serialize};
use thiserror::Error;

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
}
