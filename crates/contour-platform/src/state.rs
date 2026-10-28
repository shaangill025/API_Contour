use crate::PlatformError;
use std::{collections::HashMap, time::Instant};

pub(crate) struct Login {
    pub nonce: String,
    pub verifier: String,
    pub binding: String,
    pub expires: Instant,
}
pub(crate) struct Session {
    pub token: String,
    pub nonce: String,
    pub expires: Instant,
}
#[derive(Default)]
pub(crate) struct Memory {
    logins: HashMap<String, Login>,
    sessions: HashMap<String, Session>,
}
impl Memory {
    pub fn expire(&mut self, now: Instant) {
        self.logins.retain(|_, login| login.expires > now);
        self.sessions.retain(|_, session| session.expires > now);
    }
    pub fn insert_login(
        &mut self,
        state: String,
        login: Login,
        now: Instant,
    ) -> Result<(), PlatformError> {
        self.expire(now);
        if self.logins.len() >= 512 || self.logins.contains_key(&state) {
            return Err(PlatformError::Capacity);
        }
        self.logins.insert(state, login);
        Ok(())
    }
    pub fn consume_login(
        &mut self,
        state: &str,
        binding: &str,
        now: Instant,
    ) -> Result<Login, PlatformError> {
        self.expire(now);
        let login = self
            .logins
            .remove(state)
            .ok_or(PlatformError::Unauthenticated)?;
        if login.binding != binding {
            return Err(PlatformError::Unauthenticated);
        }
        Ok(login)
    }
    pub fn insert_session(
        &mut self,
        id: String,
        session: Session,
        now: Instant,
    ) -> Result<(), PlatformError> {
        self.expire(now);
        if self.sessions.len() >= 256 || self.sessions.contains_key(&id) {
            return Err(PlatformError::Capacity);
        }
        self.sessions.insert(id, session);
        Ok(())
    }
    pub fn verified_session(
        &mut self,
        id: &str,
        verifier: &contour_auth::IdTokenVerifier,
        unix_now: u64,
        now: Instant,
    ) -> Result<contour_auth::VerifiedIdentity, PlatformError> {
        self.expire(now);
        let session = self
            .sessions
            .get(id)
            .ok_or(PlatformError::Unauthenticated)?;
        let result = verifier
            .verify(&session.token, &session.nonce, unix_now)
            .map_err(|_| PlatformError::Unauthenticated);
        if result.is_err() {
            self.remove_session(id);
        }
        result
    }
    pub fn remove_session(&mut self, id: &str) {
        self.sessions.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn login(expires: Instant) -> Login {
        Login {
            nonce: "nonce".into(),
            verifier: "verifier".into(),
            binding: "browser-a".into(),
            expires,
        }
    }
    fn session(expires: Instant) -> Session {
        Session {
            token: "private".into(),
            nonce: "nonce".into(),
            expires,
        }
    }
    #[test]
    fn retained_session_rechecks_real_signature_nonce_and_current_expiry() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ring::{
            rand::SystemRandom,
            signature::{RSA_PKCS1_SHA256, RsaKeyPair},
        };
        let issuer = "https://idp.example.test/realms/demo";
        let verifier = contour_auth::IdTokenVerifier::new(
            issuer,
            "apicontour",
            include_bytes!("../../contour-auth/tests/fixtures/public-jwks.json"),
        )
        .unwrap();
        let key_bytes = include_bytes!("../../contour-auth/tests/fixtures/synthetic-rsa.der");
        let key = RsaKeyPair::from_der(key_bytes)
            .or_else(|_| RsaKeyPair::from_pkcs8(key_bytes))
            .unwrap();
        let claims = serde_json::json!({"iss":issuer,"sub":"synthetic","aud":"apicontour","exp":1_800_000_010u64,"iat":1_800_000_000u64,"nonce":"nonce"});
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"synthetic-rsa","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0; key.public().modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            message.as_bytes(),
            &mut signature,
        )
        .unwrap();
        let token = format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature));
        let now = Instant::now();
        let mut memory = Memory::default();
        memory
            .insert_session(
                "id".into(),
                Session {
                    token: token.clone(),
                    nonce: "nonce".into(),
                    expires: now + Duration::from_secs(1800),
                },
                now,
            )
            .unwrap();
        assert_eq!(
            memory
                .verified_session("id", &verifier, 1_800_000_000, now)
                .unwrap()
                .subject(),
            "synthetic"
        );
        assert!(matches!(
            memory.verified_session("id", &verifier, 1_800_000_010, now),
            Err(PlatformError::Unauthenticated)
        ));
        assert!(!memory.sessions.contains_key("id"));
        memory
            .insert_session(
                "wrong-nonce".into(),
                Session {
                    token,
                    nonce: "different".into(),
                    expires: now + Duration::from_secs(1800),
                },
                now,
            )
            .unwrap();
        assert!(
            memory
                .verified_session("wrong-nonce", &verifier, 1_800_000_000, now)
                .is_err()
        );
        assert!(!memory.sessions.contains_key("wrong-nonce"));
    }
    #[test]
    fn browser_binding_consumption_and_replay() {
        let now = Instant::now();
        let mut memory = Memory::default();
        memory
            .insert_login("state".into(), login(now + Duration::from_secs(1)), now)
            .unwrap();
        assert!(matches!(
            memory.consume_login("state", "browser-b", now),
            Err(PlatformError::Unauthenticated)
        ));
        assert!(memory.consume_login("state", "browser-a", now).is_err());
        memory
            .insert_login("new".into(), login(now + Duration::from_secs(1)), now)
            .unwrap();
        assert!(memory.consume_login("new", "browser-a", now).is_ok());
        assert!(memory.consume_login("new", "browser-a", now).is_err());
    }
    #[test]
    fn exact_expiry_boundary_and_session_logout() {
        let now = Instant::now();
        let expires = now + Duration::from_secs(1);
        let mut memory = Memory::default();
        memory
            .insert_login("state".into(), login(expires), now)
            .unwrap();
        memory
            .insert_session("id".into(), session(expires), now)
            .unwrap();
        assert!(memory.consume_login("state", "browser-a", expires).is_err());
        assert!(!memory.sessions.contains_key("id"));
        memory
            .insert_session("id2".into(), session(expires), now)
            .unwrap();
        memory.remove_session("id2");
        assert!(!memory.sessions.contains_key("id2"));
    }
    #[test]
    fn bounded_memory_reclaims_expired_only_and_rejects_collisions() {
        let now = Instant::now();
        let expires = now + Duration::from_secs(1);
        let mut memory = Memory::default();
        for i in 0..512 {
            memory
                .insert_login(i.to_string(), login(expires), now)
                .unwrap();
        }
        assert_eq!(
            memory.insert_login("extra".into(), login(expires), now),
            Err(PlatformError::Capacity)
        );
        assert!(memory.consume_login("0", "browser-a", now).is_ok());
        assert_eq!(
            memory.insert_login("1".into(), login(expires), now),
            Err(PlatformError::Capacity)
        );
        assert!(
            memory
                .insert_login(
                    "fresh".into(),
                    login(expires + Duration::from_secs(1)),
                    expires
                )
                .is_ok()
        );
        for i in 0..256 {
            memory
                .insert_session(i.to_string(), session(expires), now)
                .unwrap();
        }
        assert_eq!(
            memory.insert_session("extra".into(), session(expires), now),
            Err(PlatformError::Capacity)
        );
        memory.expire(expires);
        assert!(memory.sessions.is_empty());
        assert_eq!(memory.logins.len(), 1);
    }
}
