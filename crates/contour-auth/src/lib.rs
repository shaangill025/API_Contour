//! Configured OIDC ID-token verification. No network I/O or resource authorization.
mod wire;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use std::fmt;
use wire::{Claims, Header, Jwks, Object, text};

pub const MAX_ID_TOKEN_BYTES: usize = 16_384;
pub const MAX_JWKS_BYTES: usize = 65_536;
const MAX_HEADER_BYTES: usize = 2048;

/// Closed diagnostics never contain submitted tokens, claims or key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    Configuration,
    TooLarge,
    InvalidToken,
}
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AuthError {}

struct ApprovedKey {
    kid: String,
    key: DecodingKey,
}

/// An immutable operator configuration. Caller-supplied token URLs never select trust.
pub struct IdTokenVerifier {
    issuer: String,
    audience: String,
    keys: Vec<ApprovedKey>,
    validation: Validation,
}
impl fmt::Debug for IdTokenVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdTokenVerifier")
    }
}

/// Verified OIDC identity only. Map (issuer, subject) to an enabled application
/// actor and authorize tenant/project/service membership separately on every operation.
pub struct VerifiedIdentity {
    issuer: String,
    subject: String,
    expires_at: u64,
}
impl fmt::Debug for VerifiedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedIdentity")
    }
}
impl VerifiedIdentity {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}
impl IdTokenVerifier {
    /// Configuration comes from the operator, never claims/request fields.
    /// Accept up to 32 supplied public RSA keys with unique key IDs. This method
    /// performs no discovery, certificate fetching or network access.
    pub fn new(issuer: &str, client_id: &str, public_jwks: &[u8]) -> Result<Self, AuthError> {
        if !text(issuer, 1024)
            || !issuer.parse::<http::Uri>().is_ok_and(|uri| {
                uri.scheme_str() == Some("https")
                    && uri.authority().is_some_and(|authority| {
                        !authority.host().is_empty() && !authority.as_str().contains('@')
                    })
                    && uri.query().is_none()
                    && !issuer.contains('#')
            })
            || !text(client_id, 256)
            || public_jwks.len() > MAX_JWKS_BYTES
        {
            return Err(AuthError::Configuration);
        }
        let jwks: Object<Jwks> =
            serde_json::from_slice(public_jwks).map_err(|_| AuthError::Configuration)?;
        if jwks.0.keys.0.is_empty() {
            return Err(AuthError::Configuration);
        }
        let mut keys = Vec::<ApprovedKey>::new();
        for Object(jwk) in jwks.0.keys.0 {
            if jwk.kty != "RSA"
                || !text(&jwk.kid, 256)
                || jwk.alg.as_deref().is_some_and(|alg| alg != "RS256")
                || jwk.usage.as_deref().is_some_and(|usage| usage != "sig")
                || jwk
                    .key_ops
                    .as_ref()
                    .is_some_and(|ops| ops.0.as_slice() != ["verify"])
                || keys.iter().any(|key| key.kid == jwk.kid)
            {
                return Err(AuthError::Configuration);
            }
            let n = URL_SAFE_NO_PAD
                .decode(&jwk.n)
                .map_err(|_| AuthError::Configuration)?;
            let e = URL_SAFE_NO_PAD
                .decode(&jwk.e)
                .map_err(|_| AuthError::Configuration)?;
            if !(256..=1024).contains(&n.len())
                || n[0] == 0
                || n.len() * 8 - (n[0].leading_zeros() as usize) < 2048
                || n.last().is_none_or(|byte| byte & 1 == 0)
                || e.is_empty()
                || e.len() > 8
                || e[0] == 0
                || e.last().is_none_or(|byte| byte & 1 == 0)
                || (e.len() == 1 && e[0] < 3)
            {
                return Err(AuthError::Configuration);
            }
            let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
                .map_err(|_| AuthError::Configuration)?;
            keys.push(ApprovedKey { kid: jwk.kid, key });
        }
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[client_id]);
        validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
        // All time checks below use the caller's trusted clock, with no leeway.
        // This avoids hidden process-global time and permits exact boundary tests.
        validation.validate_exp = false;
        validation.validate_nbf = false;
        Ok(Self {
            issuer: issuer.to_owned(),
            audience: client_id.to_owned(),
            keys,
            validation,
        })
    }

    /// `expected_nonce` is from the server's one-use login transaction; `now_unix`
    /// is the server's trusted UTC clock, not a submitted request timestamp.
    /// Call again when using a retained ID token; this result is not authorization.
    pub fn verify(
        &self,
        token: &str,
        expected_nonce: &str,
        now_unix: u64,
    ) -> Result<VerifiedIdentity, AuthError> {
        if token.len() > MAX_ID_TOKEN_BYTES {
            return Err(AuthError::TooLarge);
        }
        if !text(expected_nonce, 256) {
            return Err(AuthError::Configuration);
        }
        let mut parts = token.split('.');
        let header = parts.next().ok_or(AuthError::InvalidToken)?;
        if parts.next().is_none_or(str::is_empty)
            || parts.next().is_none_or(str::is_empty)
            || parts.next().is_some()
            || header.len() > MAX_HEADER_BYTES * 4 / 3 + 4
        {
            return Err(AuthError::InvalidToken);
        }
        let header = URL_SAFE_NO_PAD
            .decode(header)
            .map_err(|_| AuthError::InvalidToken)?;
        if header.len() > MAX_HEADER_BYTES {
            return Err(AuthError::InvalidToken);
        }
        let Object(header): Object<Header> =
            serde_json::from_slice(&header).map_err(|_| AuthError::InvalidToken)?;
        if header.alg != "RS256"
            || !text(&header.kid, 256)
            || header.typ.as_deref().is_some_and(|typ| typ != "JWT")
        {
            return Err(AuthError::InvalidToken);
        }
        let key = self
            .keys
            .iter()
            .find(|key| key.kid == header.kid)
            .ok_or(AuthError::InvalidToken)?;
        let claims = decode::<Object<Claims>>(token, &key.key, &self.validation)
            .map_err(|_| AuthError::InvalidToken)?
            .claims
            .0;
        if claims.iss != self.issuer
            || !text(&claims.sub, 255)
            || !claims.sub.is_ascii()
            || !claims.aud.0.contains(&self.audience)
            || claims.exp <= now_unix
            || claims.iat > now_unix
            || claims.exp <= claims.iat
            || claims
                .nbf
                .is_some_and(|nbf| nbf > now_unix || nbf >= claims.exp)
            || !text(&claims.nonce, 256)
            || claims.nonce != expected_nonce
            || (claims.aud.0.len() > 1 && claims.azp.is_none())
            || claims
                .azp
                .as_deref()
                .is_some_and(|azp| azp != self.audience)
        {
            return Err(AuthError::InvalidToken);
        }
        Ok(VerifiedIdentity {
            issuer: self.issuer.clone(),
            subject: claims.sub,
            expires_at: claims.exp,
        })
    }
}
