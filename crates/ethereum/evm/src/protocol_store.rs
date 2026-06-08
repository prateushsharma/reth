//! ExternEVM Protocol Store — v4
//!
//! v3: designated fetcher rotation, commit-reveal binding, in-block cache.
//! v4: TLS certificate attestation verification. The reveal record now carries
//! the fetcher's attestation (cert DER, response hash, timestamp, signature).
//! `check_reveal` verifies, at the precompile read path (where the request URL
//! and thus the domain is available): commit-reveal binding, that the
//! attestation signer is the claimed validator, that the leaf certificate
//! covers the requested domain and is currently valid, and freshness.

use alloy_primitives::{keccak256, Address, B256, U256};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};

use crate::extern_proto::compute_attestation_digest;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SUBMISSION_WINDOW: u64 = 2;
pub const SUBMISSION_THRESHOLD_PERCENT: u64 = 51;
pub const API_REQUEST_GAS: u64 = 10_000;
pub const API_READ_GAS: u64 = 3_000;

// v4: attestation freshness bounds (seconds)
const ATTESTATION_MAX_AGE_SECS: u64 = 300; // reveal must be at most 5 min old
const ATTESTATION_MAX_SKEW_SECS: u64 = 60; // tolerate 1 min of clock skew ahead

// ---------------------------------------------------------------------------
// Request status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestStatus {
    Pending,
    Finalized,
    TimedOut,
}

// ---------------------------------------------------------------------------
// v4: reveal verification outcome (three-way so the precompile can fail fast)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum RevealOutcome {
    /// No (or not-yet-arrived) reveal from the designated fetcher — keep waiting.
    Pending,
    /// Commit-reveal binding AND attestation both verified — value is good.
    Verified(Vec<u8>),
    /// A reveal arrived but failed verification — definitive, stop waiting.
    Rejected(String),
}

// ---------------------------------------------------------------------------
// Core structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub request_id: B256,
    pub block_created: u64,
    pub url: String,
    pub method: String,
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
    pub response_path: String,
    pub response_type: u8,
    pub status: RequestStatus,
}

/// v2 compat — kept for protocol store and ExternalDataService
#[derive(Debug, Clone)]
pub struct ValidatorSubmission {
    pub request_id: B256,
    pub validator: Address,
    pub value: Vec<u8>,
    pub block_submitted: u64,
}

/// v3: phase 1 — commitment from designated fetcher
#[derive(Debug, Clone)]
pub struct ValidatorCommit {
    pub request_hash: B256,
    pub validator: Address,
    pub commitment: B256,
    pub received_at_ms: u64,
}

/// v3 reveal + v4 attestation — from designated fetcher
#[derive(Debug, Clone)]
pub struct ValidatorReveal {
    pub request_hash: B256,
    pub validator: Address,
    pub value: Vec<u8>,
    pub salt: [u8; 32],
    pub verified: bool, // commit-reveal binding verified (v3-level)
    // v4 attestation fields:
    pub cert_der: Vec<u8>,
    pub response_hash: B256,
    pub timestamp_secs: u64,
    pub attestation_sig: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FinalizedResult {
    pub request_id: B256,
    pub value: Vec<u8>,
    pub num_submissions: u32,
    pub finalized_at_block: u64,
}

// ---------------------------------------------------------------------------
// Store inner
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct StoreInner {
    pending: HashMap<B256, PendingRequest>,
    submissions: HashMap<B256, Vec<ValidatorSubmission>>,
    finalized: HashMap<B256, FinalizedResult>,
    validators: Vec<Address>,

    // v3: commit-reveal state keyed by (request_hash, validator)
    commits: HashMap<(B256, Address), ValidatorCommit>,
    reveals: HashMap<(B256, Address), ValidatorReveal>,

    // v3: in-block cache keyed by (request_hash, block_number)
    block_cache: HashMap<(B256, u64), Vec<u8>>,
}

// ---------------------------------------------------------------------------
// ProtocolStore
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ProtocolStore {
    inner: Arc<RwLock<StoreInner>>,
    request_nonce: Arc<AtomicU64>,
}

impl ProtocolStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreInner {
                pending: HashMap::new(),
                submissions: HashMap::new(),
                finalized: HashMap::new(),
                validators: Vec::new(),
                commits: HashMap::new(),
                reveals: HashMap::new(),
                block_cache: HashMap::new(),
            })),
            request_nonce: Arc::new(AtomicU64::new(0)),
        }
    }

    // -----------------------------------------------------------------------
    // Validator registry
    // -----------------------------------------------------------------------

    pub fn register_validator(&self, addr: Address) {
        let mut store = self.inner.write().unwrap();
        if !store.validators.contains(&addr) {
            store.validators.push(addr);
        }
    }

    pub fn validator_count(&self) -> usize {
        self.inner.read().unwrap().validators.len()
    }

    pub fn is_validator(&self, addr: &Address) -> bool {
        self.inner.read().unwrap().validators.contains(addr)
    }

    pub fn get_validators(&self) -> Vec<Address> {
        self.inner.read().unwrap().validators.clone()
    }

    // -----------------------------------------------------------------------
    // Designated fetcher (v3)
    // -----------------------------------------------------------------------

    pub fn designate_fetcher(&self, request_hash: B256) -> Option<Address> {
        let store = self.inner.read().unwrap();
        if store.validators.is_empty() {
            return None;
        }
        let hash_u64 = u64::from_be_bytes(request_hash.0[0..8].try_into().unwrap());
        let idx = (hash_u64 % store.validators.len() as u64) as usize;
        Some(store.validators[idx])
    }

    // -----------------------------------------------------------------------
    // In-block cache (v3)
    // -----------------------------------------------------------------------

    pub fn check_cache(&self, request_hash: B256, block_number: u64) -> Option<Vec<u8>> {
        self.inner
            .read()
            .unwrap()
            .block_cache
            .get(&(request_hash, block_number))
            .cloned()
    }

    pub fn populate_cache(&self, request_hash: B256, block_number: u64, value: Vec<u8>) {
        self.inner
            .write()
            .unwrap()
            .block_cache
            .insert((request_hash, block_number), value);
    }

    pub fn evict_old_cache_entries(&self, current_block: u64) {
        self.inner
            .write()
            .unwrap()
            .block_cache
            .retain(|&(_, block), _| block >= current_block.saturating_sub(1));
    }

    // -----------------------------------------------------------------------
    // Commit (v3)
    // -----------------------------------------------------------------------

    pub fn store_commit(&self, commit: ValidatorCommit) {
        let mut store = self.inner.write().unwrap();
        store.commits.insert((commit.request_hash, commit.validator), commit);
    }

    pub fn get_commitment(&self, request_hash: B256, validator: Address) -> Option<B256> {
        self.inner
            .read()
            .unwrap()
            .commits
            .get(&(request_hash, validator))
            .map(|c| c.commitment)
    }

    // -----------------------------------------------------------------------
    // Reveal + verification (v3 commit-reveal + v4 attestation storage)
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn store_reveal(
        &self,
        request_hash: B256,
        validator: Address,
        value: Vec<u8>,
        salt: [u8; 32],
        cert_der: Vec<u8>,
        response_hash: B256,
        timestamp_secs: u64,
        attestation_sig: Vec<u8>,
    ) -> bool {
        let mut preimage = Vec::with_capacity(value.len() + 32);
        preimage.extend_from_slice(&value);
        preimage.extend_from_slice(&salt);
        let actual_commitment = keccak256(&preimage);

        let stored_commitment = {
            let store = self.inner.read().unwrap();
            store
                .commits
                .get(&(request_hash, validator))
                .map(|c| c.commitment)
        };

        let verified = match stored_commitment {
            Some(expected) => actual_commitment == expected,
            None => {
                eprintln!(
                    "[ExternEVM] reveal from {:?} has no matching commit for request {:?}",
                    validator, request_hash
                );
                false
            }
        };

        if !verified {
            eprintln!(
                "[ExternEVM] commitment mismatch from {:?} for request {:?} — v4-zktls would close body authenticity",
                validator, request_hash
            );
        }

        self.inner.write().unwrap().reveals.insert(
            (request_hash, validator),
            ValidatorReveal {
                request_hash,
                validator,
                value,
                salt,
                verified,
                cert_der,
                response_hash,
                timestamp_secs,
                attestation_sig,
            },
        );

        verified
    }

    pub fn get_verified_reveal(&self, request_hash: B256, validator: Address) -> Option<Vec<u8>> {
        self.inner
            .read()
            .unwrap()
            .reveals
            .get(&(request_hash, validator))
            .filter(|r| r.verified)
            .map(|r| r.value.clone())
    }

    pub fn check_reveal(
        &self,
        request_hash: B256,
        validator: Address,
        domain: &str,
        now_secs: u64,
    ) -> RevealOutcome {
        let reveal = {
            let store = self.inner.read().unwrap();
            match store.reveals.get(&(request_hash, validator)) {
                Some(r) => r.clone(),
                None => return RevealOutcome::Pending,
            }
        };

        if !reveal.verified {
            return RevealOutcome::Rejected("commitment mismatch".to_string());
        }

        let digest = compute_attestation_digest(
            request_hash,
            domain,
            &reveal.cert_der,
            reveal.response_hash,
            reveal.timestamp_secs,
        );
        let signer = match recover_attestation_signer(digest, &reveal.attestation_sig) {
            Some(a) => a,
            None => return RevealOutcome::Rejected("attestation signature recovery failed".to_string()),
        };
        if signer != validator {
            return RevealOutcome::Rejected(format!(
                "attestation signer {signer:?} != designated fetcher {validator:?}"
            ));
        }

        if let Err(e) = validate_cert_for_domain(&reveal.cert_der, domain) {
            return RevealOutcome::Rejected(format!("cert validation failed: {e}"));
        }

        if !attestation_fresh(reveal.timestamp_secs, now_secs) {
            return RevealOutcome::Rejected("attestation timestamp outside freshness window".to_string());
        }

        RevealOutcome::Verified(reveal.value)
    }

    // -----------------------------------------------------------------------
    // Request lifecycle (v2 compat — kept intact)
    // -----------------------------------------------------------------------

    pub fn generate_request_id(&self, block_number: u64, tx_index: u64) -> B256 {
        let nonce = self.request_nonce.fetch_add(1, Ordering::SeqCst);
        let mut data = Vec::with_capacity(24);
        data.extend_from_slice(&block_number.to_be_bytes());
        data.extend_from_slice(&tx_index.to_be_bytes());
        data.extend_from_slice(&nonce.to_be_bytes());
        keccak256(&data)
    }

    pub fn reset_nonce(&self) {
        self.request_nonce.store(0, Ordering::SeqCst);
    }

    pub fn create_request(
        &self,
        request_id: B256,
        block_number: u64,
        url: String,
        method: String,
        headers: Vec<u8>,
        body: Vec<u8>,
        response_path: String,
        response_type: u8,
    ) -> B256 {
        let request = PendingRequest {
            request_id,
            block_created: block_number,
            url,
            method,
            headers,
            body,
            response_path,
            response_type,
            status: RequestStatus::Pending,
        };
        let mut store = self.inner.write().unwrap();
        store.pending.insert(request_id, request);
        store.submissions.insert(request_id, Vec::new());
        request_id
    }

    pub fn submit_value(
        &self,
        request_id: B256,
        validator: Address,
        value: Vec<u8>,
        block_number: u64,
    ) -> Result<(), String> {
        let mut store = self.inner.write().unwrap();

        let request = store.pending.get(&request_id).ok_or("Request not found")?;

        if request.status != RequestStatus::Pending {
            return Err(format!("Request not pending, status: {:?}", request.status));
        }
        if block_number > request.block_created + SUBMISSION_WINDOW {
            return Err("Submission window closed".to_string());
        }
        if !store.validators.contains(&validator) {
            return Err("Not a registered validator".to_string());
        }

        let submissions = store
            .submissions
            .get(&request_id)
            .ok_or("Submissions list not found")?;
        if submissions.iter().any(|s| s.validator == validator) {
            return Err("Validator already submitted".to_string());
        }

        store.submissions.get_mut(&request_id).unwrap().push(ValidatorSubmission {
            request_id,
            validator,
            value,
            block_submitted: block_number,
        });
        Ok(())
    }

    pub fn get_submissions(&self, request_id: &B256) -> Vec<ValidatorSubmission> {
        self.inner
            .read()
            .unwrap()
            .submissions
            .get(request_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_requests_ready_to_finalize(&self, current_block: u64) -> Vec<PendingRequest> {
        let store = self.inner.read().unwrap();
        store
            .pending
            .values()
            .filter(|r| {
                r.status == RequestStatus::Pending
                    && current_block > r.block_created + SUBMISSION_WINDOW
            })
            .cloned()
            .collect()
    }

    pub fn get_pending_requests(&self, current_block: u64) -> Vec<PendingRequest> {
        let store = self.inner.read().unwrap();
        store
            .pending
            .values()
            .filter(|r| {
                r.status == RequestStatus::Pending
                    && current_block <= r.block_created + SUBMISSION_WINDOW
            })
            .cloned()
            .collect()
    }

    pub fn finalize_request(
        &self,
        request_id: B256,
        value: Vec<u8>,
        num_submissions: u32,
        block_number: u64,
    ) -> Result<(), String> {
        let mut store = self.inner.write().unwrap();
        let request = store.pending.get_mut(&request_id).ok_or("Request not found")?;
        request.status = RequestStatus::Finalized;
        store.finalized.insert(
            request_id,
            FinalizedResult {
                request_id,
                value,
                num_submissions,
                finalized_at_block: block_number,
            },
        );
        Ok(())
    }

    pub fn timeout_request(&self, request_id: B256) -> Result<(), String> {
        let mut store = self.inner.write().unwrap();
        let request = store.pending.get_mut(&request_id).ok_or("Request not found")?;
        request.status = RequestStatus::TimedOut;
        Ok(())
    }

    pub fn get_finalized_result(&self, request_id: &B256) -> Option<FinalizedResult> {
        self.inner.read().unwrap().finalized.get(request_id).cloned()
    }

    pub fn get_request_status(&self, request_id: &B256) -> Option<RequestStatus> {
        self.inner
            .read()
            .unwrap()
            .pending
            .get(request_id)
            .map(|r| r.status.clone())
    }

    pub fn get_request(&self, request_id: &B256) -> Option<PendingRequest> {
        self.inner.read().unwrap().pending.get(request_id).cloned()
    }

    pub fn cleanup(&self, current_block: u64, max_age: u64) {
        let mut store = self.inner.write().unwrap();
        let to_remove: Vec<B256> = store
            .pending
            .iter()
            .filter(|(_, r)| {
                (r.status == RequestStatus::Finalized || r.status == RequestStatus::TimedOut)
                    && current_block > r.block_created + max_age
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &to_remove {
            store.pending.remove(id);
            store.submissions.remove(id);
            store.finalized.remove(id);
        }
    }
}

// ---------------------------------------------------------------------------
// v4 attestation verification helpers
// ---------------------------------------------------------------------------

fn recover_attestation_signer(digest: B256, sig: &[u8]) -> Option<Address> {
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
    if sig.len() != 65 {
        return None;
    }
    let recid = RecoveryId::try_from(sig[64] as i32).ok()?;
    let rec_sig = RecoverableSignature::from_compact(&sig[..64], recid).ok()?;
    let secp = secp256k1::Secp256k1::new();
    let msg = secp256k1::Message::from_digest(digest.0);
    let pubkey = secp.recover_ecdsa(&msg, &rec_sig).ok()?;
    let uncompressed = pubkey.serialize_uncompressed();
    let hash = keccak256(&uncompressed[1..]);
    Some(Address::from_slice(&hash[12..]))
}

fn dns_name_matches(cert_name: &str, domain: &str) -> bool {
    let cert_name = cert_name.trim().to_ascii_lowercase();
    let domain = domain.trim().to_ascii_lowercase();
    if cert_name == domain {
        return true;
    }
    if let Some(suffix) = cert_name.strip_prefix("*.") {
        if let Some(pos) = domain.find('.') {
            return &domain[pos + 1..] == suffix;
        }
    }
    false
}

fn validate_cert_for_domain(cert_der: &[u8], domain: &str) -> Result<(), String> {
    use x509_parser::prelude::*;
    if cert_der.is_empty() {
        return Err("empty certificate".to_string());
    }
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|_| "certificate failed to parse as X.509 DER".to_string())?;

    if !cert.validity().is_valid() {
        return Err("certificate outside its validity period".to_string());
    }

    let mut matched = false;
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::DNSName(name) = gn {
                if dns_name_matches(name, domain) {
                    matched = true;
                    break;
                }
            }
        }
    }
    if !matched {
        for cn in cert.subject().iter_common_name() {
            if let Ok(name) = cn.as_str() {
                if dns_name_matches(name, domain) {
                    matched = true;
                    break;
                }
            }
        }
    }

    if matched {
        Ok(())
    } else {
        Err(format!("certificate does not cover domain '{domain}'"))
    }
}

fn attestation_fresh(timestamp_secs: u64, now_secs: u64) -> bool {
    if timestamp_secs > now_secs + ATTESTATION_MAX_SKEW_SECS {
        return false;
    }
    now_secs.saturating_sub(timestamp_secs) <= ATTESTATION_MAX_AGE_SECS
}

// ---------------------------------------------------------------------------
// Aggregation helpers (v2 compat — kept)
// ---------------------------------------------------------------------------

pub fn compute_median_uint256(values: &mut Vec<U256>) -> Option<U256> {
    if values.is_empty() {
        return None;
    }
    values.sort();
    let len = values.len();
    if len % 2 == 0 {
        Some((values[len / 2 - 1] + values[len / 2]) / U256::from(2))
    } else {
        Some(values[len / 2])
    }
}

pub fn compute_majority_string(values: &[String]) -> Option<String> {
    if values.is_empty() {
        return None;
    }
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for v in values {
        *counts.entry(v.as_str()).or_insert(0) += 1;
    }
    let threshold = values.len() / 2;
    counts
        .into_iter()
        .filter(|(_, count)| *count > threshold)
        .max_by_key(|(_, count)| *count)
        .map(|(s, _)| s.to_string())
}

pub fn compute_majority_bool(values: &[bool]) -> Option<bool> {
    if values.is_empty() {
        return None;
    }
    let true_count = values.iter().filter(|&&v| v).count();
    let threshold = values.len() / 2;
    if true_count > threshold {
        Some(true)
    } else if (values.len() - true_count) > threshold {
        Some(false)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

static GLOBAL_STORE: std::sync::LazyLock<ProtocolStore> =
    std::sync::LazyLock::new(ProtocolStore::new);

pub fn global_store() -> &'static ProtocolStore {
    &GLOBAL_STORE
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn test_store() -> ProtocolStore {
        let store = ProtocolStore::new();
        store.register_validator(address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"));
        store.register_validator(address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"));
        store.register_validator(address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"));
        store
    }

    #[test]
    fn test_create_request_and_read() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);
        store.create_request(rid, 100, "https://api.example.com/price".into(), "GET".into(), vec![], vec![], "price".into(), 1);
        let req = store.get_request(&rid).unwrap();
        assert_eq!(req.url, "https://api.example.com/price");
        assert_eq!(req.status, RequestStatus::Pending);
    }

    #[test]
    fn test_submit_and_finalize() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);
        let v1 = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let v2 = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
        store.create_request(rid, 100, "https://api.example.com/price".into(), "GET".into(), vec![], vec![], "price".into(), 1);
        store.submit_value(rid, v1, vec![1, 2, 3], 101).unwrap();
        store.submit_value(rid, v2, vec![4, 5, 6], 101).unwrap();
        assert_eq!(store.get_submissions(&rid).len(), 2);
        store.finalize_request(rid, vec![7, 8, 9], 2, 103).unwrap();
        let result = store.get_finalized_result(&rid).unwrap();
        assert_eq!(result.value, vec![7, 8, 9]);
        assert_eq!(store.get_request_status(&rid).unwrap(), RequestStatus::Finalized);
    }

    #[test]
    fn test_duplicate_submission_rejected() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);
        let v1 = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        store.create_request(rid, 100, "https://api.example.com".into(), "GET".into(), vec![], vec![], "value".into(), 1);
        store.submit_value(rid, v1, vec![1, 2], 100).unwrap();
        assert_eq!(store.submit_value(rid, v1, vec![3, 4], 101).unwrap_err(), "Validator already submitted");
    }

    #[test]
    fn test_submission_window_enforced() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);
        let v1 = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        store.create_request(rid, 100, "https://api.example.com".into(), "GET".into(), vec![], vec![], "value".into(), 1);
        assert_eq!(store.submit_value(rid, v1, vec![1, 2], 103).unwrap_err(), "Submission window closed");
    }

    #[test]
    fn test_unregistered_validator_rejected() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);
        let unknown = address!("dead000000000000000000000000000000000000");
        store.create_request(rid, 100, "https://api.example.com".into(), "GET".into(), vec![], vec![], "value".into(), 1);
        assert_eq!(store.submit_value(rid, unknown, vec![1, 2], 100).unwrap_err(), "Not a registered validator");
    }

    #[test]
    fn test_timeout() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);
        store.create_request(rid, 100, "https://api.example.com".into(), "GET".into(), vec![], vec![], "value".into(), 1);
        store.timeout_request(rid).unwrap();
        assert_eq!(store.get_request_status(&rid).unwrap(), RequestStatus::TimedOut);
    }

    #[test]
    fn test_median_odd() {
        let mut vals = vec![U256::from(100), U256::from(300), U256::from(200)];
        assert_eq!(compute_median_uint256(&mut vals), Some(U256::from(200)));
    }

    #[test]
    fn test_median_single_liar() {
        let mut vals = vec![U256::from(104230), U256::from(999999999), U256::from(104232)];
        assert_eq!(compute_median_uint256(&mut vals), Some(U256::from(104232)));
    }

    #[test]
    fn test_majority_string() {
        let vals = vec!["sunny".into(), "sunny".into(), "cloudy".into()];
        assert_eq!(compute_majority_string(&vals), Some("sunny".into()));
    }

    #[test]
    fn test_majority_bool() {
        assert_eq!(compute_majority_bool(&[true, true, false]), Some(true));
    }

    #[test]
    fn test_designate_fetcher_deterministic() {
        let store = test_store();
        let hash = B256::from([0xAAu8; 32]);
        let f1 = store.designate_fetcher(hash);
        let f2 = store.designate_fetcher(hash);
        assert_eq!(f1, f2);
        assert!(f1.is_some());
    }

    #[test]
    fn test_designate_fetcher_empty() {
        let store = ProtocolStore::new();
        assert!(store.designate_fetcher(B256::from([0u8; 32])).is_none());
    }

    #[test]
    fn test_designate_fetcher_distribution() {
        let store = test_store();
        let mut seen = std::collections::HashSet::new();
        for i in 0u8..=255 {
            let mut h = [0u8; 32];
            h[0] = i;
            let hash = B256::from(h);
            if let Some(f) = store.designate_fetcher(hash) {
                seen.insert(f);
            }
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn test_in_block_cache_roundtrip() {
        let store = ProtocolStore::new();
        let hash = B256::from([0x01u8; 32]);
        store.populate_cache(hash, 10, vec![1, 2, 3]);
        assert_eq!(store.check_cache(hash, 10), Some(vec![1, 2, 3]));
        assert!(store.check_cache(hash, 11).is_none());
    }

    #[test]
    fn test_evict_old_cache_entries() {
        let store = ProtocolStore::new();
        let hash = B256::from([0x02u8; 32]);
        store.populate_cache(hash, 5, vec![9, 9, 9]);
        store.evict_old_cache_entries(10);
        assert!(store.check_cache(hash, 5).is_none());
    }

    #[test]
    fn test_commit_reveal_happy_path() {
        let store = ProtocolStore::new();
        let request_hash = B256::from([0xBBu8; 32]);
        let validator = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let value = vec![0u8; 31].into_iter().chain([42u8]).collect::<Vec<_>>();
        let salt = [0xCCu8; 32];

        let mut preimage = value.clone();
        preimage.extend_from_slice(&salt);
        let commitment = keccak256(&preimage);

        store.store_commit(ValidatorCommit { request_hash, validator, commitment, received_at_ms: 0 });

        let verified = store.store_reveal(
            request_hash, validator, value.clone(), salt,
            vec![], B256::ZERO, 0, vec![],
        );
        assert!(verified);
        assert_eq!(store.get_verified_reveal(request_hash, validator), Some(value));
    }

    #[test]
    fn test_commit_reveal_mismatch() {
        let store = ProtocolStore::new();
        let request_hash = B256::from([0xCCu8; 32]);
        let validator = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
        let value = vec![1, 2, 3, 4];
        let salt = [0xAAu8; 32];
        let wrong_salt = [0xBBu8; 32];

        let mut preimage = value.clone();
        preimage.extend_from_slice(&salt);
        let commitment = keccak256(&preimage);

        store.store_commit(ValidatorCommit { request_hash, validator, commitment, received_at_ms: 0 });

        let verified = store.store_reveal(
            request_hash, validator, value, wrong_salt,
            vec![], B256::ZERO, 0, vec![],
        );
        assert!(!verified);
        assert!(store.get_verified_reveal(request_hash, validator).is_none());
    }

    #[test]
    fn test_reveal_without_commit_fails() {
        let store = ProtocolStore::new();
        let request_hash = B256::from([0xDDu8; 32]);
        let validator = address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
        let verified = store.store_reveal(
            request_hash, validator, vec![1, 2, 3], [0u8; 32],
            vec![], B256::ZERO, 0, vec![],
        );
        assert!(!verified);
    }

    #[test]
    fn test_cleanup() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);
        store.create_request(rid, 100, "https://api.example.com".into(), "GET".into(), vec![], vec![], "value".into(), 1);
        store.finalize_request(rid, vec![1, 2, 3], 1, 103).unwrap();
        store.cleanup(140, 50);
        assert!(store.get_request(&rid).is_some());
        store.cleanup(200, 50);
        assert!(store.get_request(&rid).is_none());
        assert!(store.get_finalized_result(&rid).is_none());
    }

    #[test]
    fn test_recover_attestation_signer() {
        use secp256k1::{Secp256k1, SecretKey, Message};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let unc = pk.serialize_uncompressed();
        let addr = Address::from_slice(&keccak256(&unc[1..])[12..]);

        let digest = B256::from([0x42u8; 32]);
        let msg = Message::from_digest(digest.0);
        let recoverable = secp.sign_ecdsa_recoverable(&msg, &sk);
        let (recid, compact) = recoverable.serialize_compact();
        let mut sig = compact.to_vec();
        sig.push(i32::from(recid) as u8);

        assert_eq!(recover_attestation_signer(digest, &sig), Some(addr));
        assert_ne!(recover_attestation_signer(B256::from([0x43u8; 32]), &sig), Some(addr));
        assert_eq!(recover_attestation_signer(digest, &[0u8; 10]), None);
    }

    #[test]
    fn test_dns_name_matches() {
        assert!(dns_name_matches("api.coingecko.com", "api.coingecko.com"));
        assert!(dns_name_matches("API.CoinGecko.com", "api.coingecko.com"));
        assert!(dns_name_matches("*.coingecko.com", "api.coingecko.com"));
        assert!(!dns_name_matches("*.coingecko.com", "coingecko.com"));
        assert!(!dns_name_matches("*.coingecko.com", "a.b.coingecko.com"));
        assert!(!dns_name_matches("api.coingecko.com", "api.evil.com"));
    }

    #[test]
    fn test_attestation_fresh() {
        assert!(attestation_fresh(1000, 1000));
        assert!(attestation_fresh(1000, 1200));
        assert!(!attestation_fresh(1000, 1400));
        assert!(attestation_fresh(1000, 990));
        assert!(!attestation_fresh(1000, 900));
    }

    #[test]
    fn test_validate_cert_garbage_rejected() {
        assert!(validate_cert_for_domain(&[], "api.coingecko.com").is_err());
        assert!(validate_cert_for_domain(&[0x00, 0x01, 0x02, 0x03], "api.coingecko.com").is_err());
    }

    #[test]
    fn test_check_reveal_pending_when_absent() {
        let store = ProtocolStore::new();
        let rh = B256::from([0x66u8; 32]);
        let v = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert!(matches!(store.check_reveal(rh, v, "api.x.com", 1000), RevealOutcome::Pending));
    }

    #[test]
    fn test_check_reveal_rejects_commit_mismatch() {
        let store = ProtocolStore::new();
        let rh = B256::from([0x55u8; 32]);
        let v = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let value = vec![1, 2, 3, 4];
        let salt = [0xAAu8; 32];
        let mut preimage = value.clone();
        preimage.extend_from_slice(&salt);
        let commitment = keccak256(&preimage);
        store.store_commit(ValidatorCommit { request_hash: rh, validator: v, commitment, received_at_ms: 0 });
        store.store_reveal(rh, v, value, [0xBBu8; 32], vec![], B256::ZERO, 0, vec![]);
        assert!(matches!(store.check_reveal(rh, v, "api.x.com", 1000), RevealOutcome::Rejected(_)));
    }
}
