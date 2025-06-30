#![no_main]

use libfuzzer_sys::fuzz_target;
use kindly_guard_server::{auth::{TokenValidator, TokenGenerator, AuthConfig}, ServerConfig};
use arbitrary::{Arbitrary, Unstructured};

// Arbitrary token generation strategies
#[derive(Debug, Clone)]
enum TokenStrategy {
    ValidFormat,
    InvalidBase64,
    TamperedSignature,
    ExpiredToken,
    WrongAlgorithm,
    MissingClaims,
    ExtraClaims,
    RandomBytes,
}

impl<'a> Arbitrary<'a> for TokenStrategy {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=7)? {
            0 => Ok(TokenStrategy::ValidFormat),
            1 => Ok(TokenStrategy::InvalidBase64),
            2 => Ok(TokenStrategy::TamperedSignature),
            3 => Ok(TokenStrategy::ExpiredToken),
            4 => Ok(TokenStrategy::WrongAlgorithm),
            5 => Ok(TokenStrategy::MissingClaims),
            6 => Ok(TokenStrategy::ExtraClaims),
            _ => Ok(TokenStrategy::RandomBytes),
        }
    }
}

fn generate_token(strategy: &TokenStrategy, data: &[u8]) -> String {
    match strategy {
        TokenStrategy::ValidFormat => {
            // Generate a properly formatted JWT-like token
            let header = base64::encode(r#"{"alg":"HS256","typ":"JWT"}"#);
            let payload = base64::encode(format!(r#"{{"sub":"test","exp":{}}}
"#, 
                chrono::Utc::now().timestamp() + 3600));
            let signature = base64::encode(&data[..data.len().min(32)]);
            format!("{}.{}.{}", header, payload, signature)
        },
        TokenStrategy::InvalidBase64 => {
            // Invalid base64 characters
            format!("eyJ!@#$.eyJ$%^&*.{}!@#$", String::from_utf8_lossy(data))
        },
        TokenStrategy::TamperedSignature => {
            // Valid format but modified signature
            let header = base64::encode(r#"{"alg":"HS256","typ":"JWT"}"#);
            let payload = base64::encode(r#"{"sub":"test"}"#);
            let signature = String::from_utf8_lossy(data).replace(|c: char| !c.is_ascii(), "X");
            format!("{}.{}.{}", header, payload, signature)
        },
        TokenStrategy::ExpiredToken => {
            // Token with expired timestamp
            let header = base64::encode(r#"{"alg":"HS256","typ":"JWT"}"#);
            let payload = base64::encode(format!(r#"{{"sub":"test","exp":{}}}
"#, 
                chrono::Utc::now().timestamp() - 3600));
            let signature = base64::encode(&data[..data.len().min(32)]);
            format!("{}.{}.{}", header, payload, signature)
        },
        TokenStrategy::WrongAlgorithm => {
            // Different algorithm in header
            let header = base64::encode(r#"{"alg":"none","typ":"JWT"}"#);
            let payload = base64::encode(r#"{"sub":"test"}"#);
            format!("{}.{}", header, payload)
        },
        TokenStrategy::MissingClaims => {
            // Missing required claims
            let header = base64::encode(r#"{"alg":"HS256","typ":"JWT"}"#);
            let payload = base64::encode(r#"{}"#);
            let signature = base64::encode(&data[..data.len().min(32)]);
            format!("{}.{}.{}", header, payload, signature)
        },
        TokenStrategy::ExtraClaims => {
            // Extra/unexpected claims
            let header = base64::encode(r#"{"alg":"HS256","typ":"JWT"}"#);
            let extra_claims = format!(r#"{{"sub":"test","admin":true,"role":"superuser","random":"{}"}}
"#,
                String::from_utf8_lossy(data));
            let payload = base64::encode(extra_claims);
            let signature = base64::encode(&data[..data.len().min(32)]);
            format!("{}.{}.{}", header, payload, signature)
        },
        TokenStrategy::RandomBytes => {
            // Completely random data
            String::from_utf8_lossy(data).to_string()
        },
    }
}

fuzz_target!(|data: &[u8]| {
    // Test raw token validation
    let token = String::from_utf8_lossy(data);
    
    let config = AuthConfig {
        secret_key: "FUZZING-TEST-KEY-NOT-FOR-PRODUCTION".to_string(),
        token_expiry: std::time::Duration::from_secs(3600),
        require_auth: true,
    };
    
    if let Ok(validator) = TokenValidator::new(config.clone()) {
        // Should not panic on any input
        let _ = validator.validate_token(&token);
        
        // Test with Bearer prefix
        let bearer_token = format!("Bearer {}", token);
        let _ = validator.validate_token(&bearer_token);
        
        // Test with malformed Bearer
        let malformed_bearer = format!("Bearer{}", token);
        let _ = validator.validate_token(&malformed_bearer);
    }
    
    // Test with generated tokens using various strategies
    let mut u = Unstructured::new(data);
    if let Ok(strategy) = TokenStrategy::arbitrary(&mut u) {
        let generated_token = generate_token(&strategy, data);
        
        if let Ok(validator) = TokenValidator::new(config.clone()) {
            let _ = validator.validate_token(&generated_token);
            
            // Test token refresh with potentially invalid tokens
            if let Ok(generator) = TokenGenerator::new(config) {
                let _ = generator.refresh_token(&generated_token);
            }
        }
    }
    
    // Test edge cases
    if data.len() > 0 {
        // Very long tokens
        let long_token = String::from_utf8_lossy(data).repeat(100);
        if let Ok(validator) = TokenValidator::new(config.clone()) {
            let _ = validator.validate_token(&long_token);
        }
        
        // Tokens with null bytes
        let mut null_token = String::from_utf8_lossy(data).to_string();
        null_token.push('\0');
        if let Ok(validator) = TokenValidator::new(config.clone()) {
            let _ = validator.validate_token(&null_token);
        }
        
        // Unicode in tokens
        let unicode_token = format!("{}\u{202E}{}\u{202C}", 
            String::from_utf8_lossy(&data[..data.len()/2]),
            String::from_utf8_lossy(&data[data.len()/2..]));
        if let Ok(validator) = TokenValidator::new(config) {
            let _ = validator.validate_token(&unicode_token);
        }
    }
});