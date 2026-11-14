//! SQL28 fixed-purpose provisioning and comparison. No result proves TLS,
//! deployment, marker possession, bootstrap, or permit authority.
use super::*;
use contour_core::ReceiverEnrollment;

/// Operator configuration, not an authenticated peer or material attestation.
/// The caller must retain the exact same nonce and claim for any reconciliation.
pub struct ReceiverEnrollmentInputs504<'a> {
    pub product_credential_id: &'a str,
    pub product_leaf: &'a [u8; 32],
    pub export_leaf: &'a [u8; 32],
    pub backend_leaf: &'a [u8; 32],
    pub evidence_leaf: &'a [u8; 32],
    pub provision_nonce: &'a [u8; 32],
    pub backend_not_before: OffsetDateTime,
    pub backend_not_after: OffsetDateTime,
    pub evidence_not_before: OffsetDateTime,
    pub evidence_not_after: OffsetDateTime,
    pub ttl: Duration,
    pub peer: &'a [u8; 32],
    pub grant_keys: &'a CausalGrantKeys,
    pub policy_keys: &'a PolicyKeys,
}

/// Commit-confirmed data only; current SQL28 must still be read independently.
/// ```compile_fail
/// use contour_postgres::ReceiverEnrollmentReceipt504;
/// let _ = ReceiverEnrollmentReceipt504 { generation: String::new() };
/// ```
pub struct ReceiverEnrollmentReceipt504 {
    generation: String,
    credential_id: String,
    issued: OffsetDateTime,
    expires: OffsetDateTime,
    commitment: [u8; 32],
    verified_until: Instant,
}
impl ReceiverEnrollmentReceipt504 {
    pub fn generation(&self) -> &str {
        &self.generation
    }
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued
    }
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires
    }
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
    pub fn verified_until(&self) -> Instant {
        self.verified_until
    }
}
impl fmt::Debug for ReceiverEnrollmentReceipt504 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceiverEnrollmentReceipt504")
    }
}

fn validate_inputs(input: &ReceiverEnrollmentInputs504<'_>) -> Result<i64, CausalError> {
    let leaves = [
        input.product_leaf,
        input.export_leaf,
        input.backend_leaf,
        input.evidence_leaf,
    ];
    if !uuid(input.product_credential_id)
        || *input.provision_nonce == [0; 32]
        || *input.peer == [0; 32]
        || input.peer != input.export_leaf
        || leaves
            .iter()
            .enumerate()
            .any(|(i, leaf)| **leaf == [0; 32] || leaves[..i].contains(leaf))
        || input.backend_not_before >= input.backend_not_after
        || input.evidence_not_before >= input.evidence_not_after
        || input.ttl.is_zero()
        || input.ttl.as_micros() > 900_000_000
        || input.ttl.subsec_nanos() % 1000 != 0
    {
        return Err(CausalError::Scope);
    }
    // Same conservative rounding as the checked issuer: never extend validity.
    pg_time(input.backend_not_before, true)?;
    pg_time(input.backend_not_after, false)?;
    pg_time(input.evidence_not_before, true)?;
    pg_time(input.evidence_not_after, false)?;
    i64::try_from(input.ttl.as_micros()).map_err(|_| CausalError::Scope)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn sha256(bytes: &[u8]) -> Result<[u8; 32], CausalError> {
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .ok_or(CausalError::Corrupt)?;
    suite
        .common
        .hash_provider
        .hash(bytes)
        .as_ref()
        .try_into()
        .map_err(|_| CausalError::Corrupt)
}

struct ReceiptFields<'a> {
    generation: &'a str,
    credential_id: &'a str,
    issued: OffsetDateTime,
    expires: OffsetDateTime,
    commitment: &'a [u8; 32],
}
fn valid_receipt(
    receipt: &ReceiptFields<'_>,
    input: &ReceiverEnrollmentInputs504<'_>,
    ttl: i64,
    before: OffsetDateTime,
    after: OffsetDateTime,
    session_expires: OffsetDateTime,
) -> bool {
    receipt.generation.len() == 32
        && receipt
            .generation
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && receipt.generation.bytes().any(|b| b != b'0')
        && uuid(receipt.credential_id)
        && receipt.credential_id != input.product_credential_id
        && *receipt.commitment != [0; 32]
        && after >= before
        && receipt.issued <= after
        && receipt.issued < receipt.expires
        && after < receipt.expires
        && receipt.expires <= session_expires
        && receipt.issued >= input.backend_not_before
        && receipt.issued >= input.evidence_not_before
        && receipt.expires <= input.backend_not_after
        && receipt.expires <= input.evidence_not_after
        && receipt.expires - receipt.issued <= time::Duration::microseconds(ttl)
}

impl CausalReceiverSession504 {
    /// Compare untrusted decoded enrollment data with this exact signed session
    /// and caller-selected material. This does not establish current SQL state.
    pub fn matches_enrollment_until(
        &self,
        metadata: &ReceiverEnrollment,
        input: &ReceiverEnrollmentInputs504<'_>,
        deadline: Instant,
    ) -> Result<(), CausalError> {
        self.matches_enrollment_checked_at(metadata, input, deadline, OffsetDateTime::now_utc())
    }

    fn matches_enrollment_checked_at(
        &self,
        metadata: &ReceiverEnrollment,
        input: &ReceiverEnrollmentInputs504<'_>,
        deadline: Instant,
        now: OffsetDateTime,
    ) -> Result<(), CausalError> {
        validate_inputs(input)?;
        let s = &self.session;
        receiver_owner_entry_check(s, input.peer, deadline)?;
        let (grant, policy) = verify(
            &s.issue,
            input.peer,
            input.grant_keys,
            input.policy_keys,
            now,
        )?;
        let ids = &s.issue.binding.ids;
        if now < s.issued
            || now >= s.expires
            || now < metadata.issued_at().instant()
            || now >= metadata.expires_at().instant()
            || metadata.issued_at().instant() < s.issued
            || metadata.expires_at().instant() > s.expires
            || metadata.evidence_credential_id() == input.product_credential_id
            || metadata.expires_at().instant() - metadata.issued_at().instant()
                > time::Duration::try_from(input.ttl).map_err(|_| CausalError::Scope)?
            || metadata.tenant_id() != ids[0]
            || metadata.runtime_id() != ids[1]
            || metadata.instance_id() != ids[8]
            || metadata.lifecycle_id() != ids[9]
            || metadata.session_nonce() != s.issue.nonce
            || metadata.session_epoch() != s.epoch
            || metadata.profile_id() != "00000000-0000-4000-8000-000000000504"
            || metadata.profile_manifest_sha256() != RECEIVER_MANIFEST
            || metadata.artifact_sha256()
                != "707e7b359fb757c668d8a22c999e067556b5f2a785f9c3333c12fca7debfa660"
            || metadata.grant_digest() != hex(&s.digest)
            || grant.payload_digest() != s.digest
            || metadata.policy_revision() != policy.revision()
            || metadata.policy_envelope_sha256() != hex(&sha256(&s.issue.policy)?)
            || metadata.product_credential_id() != input.product_credential_id
            || metadata.product_leaf_sha256() != hex(input.product_leaf)
            || metadata.export_leaf_sha256() != hex(input.export_leaf)
            || metadata.backend_leaf_sha256() != hex(input.backend_leaf)
            || metadata.evidence_leaf_sha256() != hex(input.evidence_leaf)
            || metadata.issued_at().instant() < input.backend_not_before
            || metadata.issued_at().instant() < input.evidence_not_before
            || metadata.expires_at().instant() > input.backend_not_after
            || metadata.expires_at().instant() > input.evidence_not_after
        {
            return Err(CausalError::Scope);
        }
        receiver_owner_entry_check(s, input.peer, deadline)
    }
}

/// Connection must have only the dedicated evidence-provisioner role.
/// ```compile_fail
/// use contour_postgres::{CausalSession, ReceiverEnrollmentInputs504, ReceiverEnrollmentProvisioner504};
/// async fn legacy(p: &mut ReceiverEnrollmentProvisioner504, s: &mut CausalSession, i: &ReceiverEnrollmentInputs504<'_>) {
///     p.enroll_until(s, i, tokio::time::Instant::now()).await.unwrap();
/// }
/// ```
pub struct ReceiverEnrollmentProvisioner504 {
    connection: ConnectedDatabase,
}
impl ReceiverEnrollmentProvisioner504 {
    pub fn new(connection: ConnectedDatabase) -> Self {
        Self { connection }
    }
    pub fn into_database(self) -> ConnectedDatabase {
        self.connection
    }
    /// One fixed SQL28 attempt. Unknown commit and cancellation invalidate the
    /// borrowed session. This method never retries automatically.
    pub async fn enroll_until(
        &mut self,
        session: &mut CausalReceiverSession504,
        input: &ReceiverEnrollmentInputs504<'_>,
        deadline: Instant,
    ) -> Result<ReceiverEnrollmentReceipt504, CausalError> {
        let mut session_guard = MarkerSessionGuard {
            session: &mut session.session,
            succeeded: false,
        };
        let result = self
            .enroll_checked(session_guard.session, input, deadline)
            .await;
        session_guard.succeeded = result.is_ok();
        result
    }
    async fn enroll_checked(
        &mut self,
        session: &mut CausalSession,
        input: &ReceiverEnrollmentInputs504<'_>,
        deadline: Instant,
    ) -> Result<ReceiverEnrollmentReceipt504, CausalError> {
        let ttl = validate_inputs(input)?;
        receiver_owner_entry_check(session, input.peer, deadline)?;
        let deadline = deadline
            .min(session.verified_until)
            .min(Instant::now() + self.connection.deadline);
        check_deadline(deadline)?;
        let starts = [
            pg_time(input.backend_not_before, true)?,
            pg_time(input.backend_not_after, false)?,
            pg_time(input.evidence_not_before, true)?,
            pg_time(input.evidence_not_after, false)?,
        ];
        let mut guard = CancellationGuard::arm(&mut self.connection);
        let mut committing = false;
        let mut tightened = None;
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(CausalError::Database)?;
            check_role(client, "contour_causal_evidence_provisioner").await?;
            let tx = begin(client).await?;
            let preparation=async {
                let ids=&session.issue.binding.ids;
                configure_tenant(&tx,&ids[0],deadline.saturating_duration_since(Instant::now())).await?;
                let now=clock(&tx).await?;
                let (grant,_)=verify(&session.issue,input.peer,input.grant_keys,input.policy_keys,now)?;
                if grant.payload_digest()!=session.digest || now<session.issued || now>=session.expires || now<input.backend_not_before || now>=input.backend_not_after || now<input.evidence_not_before || now>=input.evidence_not_after { return Err(CausalError::Expired); }
                let epoch=session.epoch.to_string();
                check_deadline(deadline)?;
                let row=tx.query_one("SELECT generation,credential_id::text,floor(extract(epoch FROM issued_at)*1000000)::bigint,floor(extract(epoch FROM expires_at)*1000000)::bigint,commitment FROM contour.enroll_causal_receiver(ROW($1::text::uuid,$2::text::uuid,$3::text::numeric,$4::text::uuid,$5::text::uuid,$6::text::uuid,$7::bytea,$8::bytea,$9::bytea,$10::bytea,$11::bytea,$12::text::timestamptz,$13::text::timestamptz,$14::text::timestamptz,$15::text::timestamptz,$16::bigint)::contour.receiver_enrollment_claim)", &[&ids[0],&ids[1],&epoch,&ids[8],&ids[9],&input.product_credential_id,&&input.product_leaf[..],&&input.export_leaf[..],&&input.backend_leaf[..],&&input.evidence_leaf[..],&&input.provision_nonce[..],&starts[0],&starts[1],&starts[2],&starts[3],&ttl]).await.map_err(db_error)?;
                let generation:String=row.try_get(0).map_err(|_|CausalError::Corrupt)?;
                let credential_id:String=row.try_get(1).map_err(|_|CausalError::Corrupt)?;
                let issued=time_from_micros(row.try_get(2).map_err(|_|CausalError::Corrupt)?)?;
                let expires=time_from_micros(row.try_get(3).map_err(|_|CausalError::Corrupt)?)?;
                let commitment:Vec<u8>=row.try_get(4).map_err(|_|CausalError::Corrupt)?;
                let commitment: [u8;32]=commitment.try_into().map_err(|_|CausalError::Corrupt)?;
                let final_start=Instant::now(); let final_now=clock(&tx).await?;
                let (again,_)=verify(&session.issue,input.peer,input.grant_keys,input.policy_keys,final_now)?;
                let receipt_fields=ReceiptFields { generation:&generation,credential_id:&credential_id,issued,expires,commitment:&commitment };
                if !valid_receipt(&receipt_fields,input,ttl,now,final_now,session.expires) || again.payload_digest()!=session.digest { return Err(CausalError::Corrupt); }
                let limit=claim_freshness(session.verified_until,final_start,final_now,expires,Instant::now())?.min(deadline);
                if Instant::now()>=limit {return Err(CausalError::Deadline);}
                tightened=Some(limit);
                tx.query_one("SELECT set_config('synchronous_commit','on',true)",&[]).await.map_err(nonretry_error)?;
                check_deadline(deadline)?;
                Ok::<_,CausalError>((generation,credential_id,issued,expires,commitment))
            }.await;
            match preparation {
                Ok(value) => {
                    committing = true;
                    tx.commit().await.map_err(|_| CausalError::OutcomeUnknown)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Ok(value)
                }
                Err(error) => {
                    tx.rollback().await.map_err(|_| CausalError::Database)?;
                    empty_context(client)
                        .await
                        .map_err(|_| CausalError::Database)?;
                    check_deadline(deadline)?;
                    if error != CausalError::Deadline {
                        guard.confirm();
                    }
                    Err(error)
                }
            }
        };
        let (generation, credential_id, issued, expires, commitment) =
            match timeout_at(deadline, work).await {
                Ok(Err(_)) if committing => return Err(CausalError::OutcomeUnknown),
                Ok(value) => value?,
                Err(_) if committing => return Err(CausalError::OutcomeUnknown),
                Err(_) => return Err(CausalError::Deadline),
            };
        let limit = commit_freshness(tightened.ok_or(CausalError::Expired)?, Instant::now())?;
        session.verified_until = limit;
        Ok(ReceiverEnrollmentReceipt504 {
            generation,
            credential_id,
            issued,
            expires,
            commitment,
            verified_until: limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (CausalGrantKeys, PolicyKeys) {
        let key = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        (
            CausalGrantKeys::new(&[("fixture", key)]).unwrap(),
            PolicyKeys::new(&[("fixture", key)]).unwrap(),
        )
    }
    #[test]
    fn inputs_reject_wrong_peer_reused_purpose_zero_nonce_and_bad_times() {
        let (grants, policies) = keys();
        let product = [1; 32];
        let export = [2; 32];
        let backend = [3; 32];
        let evidence = [4; 32];
        let nonce = [5; 32];
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let mut value = ReceiverEnrollmentInputs504 {
            product_credential_id: "00000000-0000-4000-8000-000000000001",
            product_leaf: &product,
            export_leaf: &export,
            backend_leaf: &backend,
            evidence_leaf: &evidence,
            provision_nonce: &nonce,
            backend_not_before: now - time::Duration::seconds(1),
            backend_not_after: now + time::Duration::seconds(30),
            evidence_not_before: now - time::Duration::seconds(1),
            evidence_not_after: now + time::Duration::seconds(30),
            ttl: Duration::from_secs(10),
            peer: &export,
            grant_keys: &grants,
            policy_keys: &policies,
        };
        assert_eq!(validate_inputs(&value), Ok(10_000_000));
        let generation = "123456789abcdef0123456789abcdef0";
        let credential = "00000000-0000-4000-8000-000000000002";
        let commit = [9; 32];
        let valid = ReceiptFields {
            generation,
            credential_id: credential,
            issued: now,
            expires: now + time::Duration::seconds(10),
            commitment: &commit,
        };
        assert!(valid_receipt(
            &valid,
            &value,
            10_000_000,
            now,
            now,
            now + time::Duration::seconds(20)
        ));
        let wrong_generation = ReceiptFields {
            generation: "00000000000000000000000000000000",
            ..valid
        };
        assert!(!valid_receipt(
            &wrong_generation,
            &value,
            10_000_000,
            now,
            now,
            now + time::Duration::seconds(20)
        ));
        let wrong_credential = ReceiptFields {
            generation,
            credential_id: value.product_credential_id,
            issued: now,
            expires: now + time::Duration::seconds(10),
            commitment: &commit,
        };
        assert!(!valid_receipt(
            &wrong_credential,
            &value,
            10_000_000,
            now,
            now,
            now + time::Duration::seconds(20)
        ));
        assert!(!valid_receipt(
            &valid,
            &value,
            9_999_999,
            now,
            now,
            now + time::Duration::seconds(20)
        ));
        assert!(!valid_receipt(
            &valid,
            &value,
            10_000_000,
            now,
            now + time::Duration::seconds(10),
            now + time::Duration::seconds(20)
        ));
        assert!(!valid_receipt(
            &valid,
            &value,
            10_000_000,
            now,
            now,
            now + time::Duration::seconds(9)
        ));
        value.peer = &product;
        assert_eq!(validate_inputs(&value), Err(CausalError::Scope));
        value.peer = &export;
        value.backend_leaf = &product;
        assert_eq!(validate_inputs(&value), Err(CausalError::Scope));
        value.backend_leaf = &backend;
        value.provision_nonce = &[0; 32];
        assert_eq!(validate_inputs(&value), Err(CausalError::Scope));
        value.provision_nonce = &nonce;
        value.product_credential_id = "00000000-0000-4000-8000-00000000000A";
        assert_eq!(validate_inputs(&value), Err(CausalError::Scope));
        value.product_credential_id = "00000000-0000-4000-8000-000000000001";
        value.ttl = Duration::from_secs(901);
        assert_eq!(validate_inputs(&value), Err(CausalError::Scope));
        value.ttl = Duration::from_nanos(1);
        assert_eq!(validate_inputs(&value), Err(CausalError::Scope));
        value.ttl = Duration::from_secs(1);
        value.backend_not_before = value.backend_not_after;
        assert_eq!(validate_inputs(&value), Err(CausalError::Scope));
    }
    #[test]
    fn signed_session_rejects_changed_enrollment_associations_at_fixture_time() {
        use contour_core::Timestamp;
        use serde_json::{Value, json};
        fn unhex(text: &str) -> [u8; 32] {
            let mut out = [0; 32];
            for (index, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
            }
            out
        }
        fn decode(body: &Value) -> Option<ReceiverEnrollment> {
            let raw = serde_json::to_vec(body).unwrap();
            let mut input = b"apicontour/receiver-enrollment/1\n".to_vec();
            input.extend_from_slice(&(raw.len() as u32).to_be_bytes());
            input.extend_from_slice(&raw);
            ReceiverEnrollment::decode(&raw, &sha256(&input).unwrap()).ok()
        }
        const ID: &str = "00000000-0000-4000-8000-000000000001";
        let signed: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/causal_candidate_504.json"
        ))
        .unwrap();
        let fixture: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/causal_bridge.json")).unwrap();
        let grants = CausalGrantKeys::new(&[(
            "receiver-fixture",
            unhex(signed["public_hex"].as_str().unwrap()),
        )])
        .unwrap();
        let policies =
            PolicyKeys::new(&[("fixture", unhex(fixture["policy_public"].as_str().unwrap()))])
                .unwrap();
        let peer = [3; 32];
        let issue = CausalIssue::new(
            CausalBinding::new([ID; 10], peer).unwrap(),
            ID,
            Duration::from_secs(60),
            &serde_json::to_vec(&signed["valid"]).unwrap(),
            &serde_json::to_vec(&fixture["policy"]).unwrap(),
        )
        .unwrap();
        let now = Timestamp::parse("2026-10-07T12:00:01Z").unwrap().instant();
        let (grant, policy) = verify(&issue, &peer, &grants, &policies, now).unwrap();
        let digest = grant.payload_digest();
        let policy_hash = sha256(&issue.policy).unwrap();
        let session = CausalReceiverSession504 {
            session: CausalSession {
                issue,
                profile: SessionProfile::Candidate504,
                epoch: 1,
                issued: now - time::Duration::seconds(1),
                expires: now + time::Duration::seconds(60),
                digest,
                verified_until: Instant::now() + Duration::from_secs(60),
            },
        };
        let product = [1; 32];
        let backend = [4; 32];
        let evidence = [5; 32];
        let nonce = [6; 32];
        let input = ReceiverEnrollmentInputs504 {
            product_credential_id: "00000000-0000-4000-8000-000000000002",
            product_leaf: &product,
            export_leaf: &peer,
            backend_leaf: &backend,
            evidence_leaf: &evidence,
            provision_nonce: &nonce,
            backend_not_before: now - time::Duration::seconds(60),
            backend_not_after: now + time::Duration::seconds(120),
            evidence_not_before: now - time::Duration::seconds(60),
            evidence_not_after: now + time::Duration::seconds(120),
            ttl: Duration::from_secs(60),
            peer: &peer,
            grant_keys: &grants,
            policy_keys: &policies,
        };
        let base = json!({"artifact_sha256":"707e7b359fb757c668d8a22c999e067556b5f2a785f9c3333c12fca7debfa660","backend_leaf_sha256":hex(&backend),"enrollment_generation":"123456789abcdef0123456789abcdef0","evidence_credential_id":"00000000-0000-4000-8000-000000000003","evidence_leaf_sha256":hex(&evidence),"expires_at":"2026-10-07T12:00:31.000000Z","export_leaf_sha256":hex(&peer),"grant_digest":hex(&digest),"instance_id":ID,"issued_at":"2026-10-07T12:00:01.000000Z","lifecycle_id":ID,"policy_envelope_sha256":hex(&policy_hash),"policy_revision":policy.revision().to_string(),"product_credential_id":input.product_credential_id,"product_leaf_sha256":hex(&product),"profile_id":"00000000-0000-4000-8000-000000000504","profile_manifest_sha256":RECEIVER_MANIFEST,"runtime_id":ID,"session_epoch":"1","session_nonce":ID,"tenant_id":ID,"version":1});
        let deadline = Instant::now() + Duration::from_secs(30);
        let positive = decode(&base).expect("positive enrollment decode");
        session
            .matches_enrollment_checked_at(&positive, &input, deadline, now)
            .expect("positive signed session association");
        let other = "00000000-0000-4000-8000-000000000004";
        for (field, changed) in [
            ("session_epoch", json!("2")),
            ("session_nonce", json!(other)),
            ("instance_id", json!(other)),
            ("lifecycle_id", json!(other)),
            ("tenant_id", json!(other)),
            ("runtime_id", json!(other)),
            ("grant_digest", json!("99".repeat(32))),
            ("policy_envelope_sha256", json!("98".repeat(32))),
            (
                "policy_revision",
                json!(if policy.revision() == 2 { "3" } else { "2" }),
            ),
            ("product_credential_id", json!(other)),
            ("product_leaf_sha256", json!("97".repeat(32))),
            ("export_leaf_sha256", json!("96".repeat(32))),
            ("backend_leaf_sha256", json!("95".repeat(32))),
            ("evidence_leaf_sha256", json!("94".repeat(32))),
            ("issued_at", json!("2026-10-07T12:00:02.000000Z")),
        ] {
            let mut changed_body = base.clone();
            changed_body[field] = changed;
            let metadata = decode(&changed_body).expect("semantic mutation must decode");
            assert!(
                session
                    .matches_enrollment_checked_at(&metadata, &input, deadline, now)
                    .is_err(),
                "changed {field}"
            );
        }
        for (field, changed) in [
            ("profile_id", json!(other)),
            ("profile_manifest_sha256", json!("93".repeat(32))),
            ("artifact_sha256", json!("92".repeat(32))),
            ("expires_at", json!("2026-10-07T12:00:00.000000Z")),
        ] {
            let mut changed_body = base.clone();
            changed_body[field] = changed;
            assert!(decode(&changed_body).is_none(), "parser rejects {field}");
        }
        let valid = positive;
        assert!(
            session
                .matches_enrollment_checked_at(
                    &valid,
                    &input,
                    deadline,
                    now + time::Duration::seconds(30)
                )
                .is_err()
        );
        assert!(
            session
                .matches_enrollment_checked_at(&valid, &input, Instant::now(), now)
                .is_err()
        );
    }
    #[test]
    fn fixed_hash_matches_known_sha256() {
        assert_eq!(
            hex(&sha256(b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
