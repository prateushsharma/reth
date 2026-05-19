//! ExternEVM Protocol Store — v2
//!
//! In-memory storage for pending API requests, validator submissions,
//! and finalized results. Accessed by precompiles (during EVM execution)
//! and by the ExternalDataService (between blocks).
//!
//! This is a singleton behind Arc<RwLock<>> so it can be shared safely.
//! For v2 single-node, this is in-memory only. Future versions will
//! persist to reth-db tables for crash recovery and multi-node sync.

use alloy_primitives::{Address, B256, U256, keccak256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock, atomic::{AtomicU64, Ordering}};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How many blocks validators have to submit their values after request creation.
pub const SUBMISSION_WINDOW: u64 = 2;

/// Minimum percentage of registered validators that must submit (>50%).
/// Represented as percentage (51 = 51%).
pub const SUBMISSION_THRESHOLD_PERCENT: u64 = 51;

/// Gas cost for API_REQUEST precompile (higher than API_CALL since it writes state).
pub const API_REQUEST_GAS: u64 = 10_000;

/// Gas cost for API_READ precompile.
pub const API_READ_GAS: u64 = 3_000;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Status of a pending API data request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestStatus {
    /// Request created, waiting for validator submissions.
    Pending,
    /// Enough submissions received, median computed, result available.
    Finalized,
    /// Submission window closed without enough participation.
    TimedOut,
}

/// A pending external data request created by a contract via API_REQUEST.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub request_id: B256,
    pub block_created: u64,
    pub url: String,
    pub method: String,
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
    pub response_path: String,
    pub response_type: u8, // 0=bytes, 1=uint256, 2=string, 3=bool
    pub status: RequestStatus,
}

/// A value submitted by a validator for a specific request.
#[derive(Debug, Clone)]
pub struct ValidatorSubmission {
    pub request_id: B256,
    pub validator: Address,
    pub value: Vec<u8>, // raw value bytes (not ABI-encoded yet)
    pub block_submitted: u64,
}

/// The finalized result after median/majority aggregation.
#[derive(Debug, Clone)]
pub struct FinalizedResult {
    pub request_id: B256,
    pub value: Vec<u8>, // ABI-encoded final result
    pub num_submissions: u32,
    pub finalized_at_block: u64,
}

// ---------------------------------------------------------------------------
// Protocol Store
// ---------------------------------------------------------------------------

/// Inner state behind the RwLock.
#[derive(Debug)]
struct StoreInner {
    /// All pending requests, keyed by request_id.
    pending: HashMap<B256, PendingRequest>,

    /// Validator submissions, keyed by (request_id, validator).
    /// Multiple validators can submit for the same request.
    submissions: HashMap<B256, Vec<ValidatorSubmission>>,

    /// Finalized results, keyed by request_id.
    finalized: HashMap<B256, FinalizedResult>,

    /// Registered validators (for threshold calculation).
    /// In v2 single-node, this starts with just the node's own address.
    validators: Vec<Address>,
}

/// Thread-safe protocol store accessible from precompiles and background services.
#[derive(Debug, Clone)]
pub struct ProtocolStore {
    inner: Arc<RwLock<StoreInner>>,
    /// Atomic counter for generating unique request IDs within a block.
    request_nonce: Arc<AtomicU64>,
}

impl ProtocolStore {
    /// Create a new empty protocol store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreInner {
                pending: HashMap::new(),
                submissions: HashMap::new(),
                finalized: HashMap::new(),
                validators: Vec::new(),
            })),
            request_nonce: Arc::new(AtomicU64::new(0)),
        }
    }

    // -----------------------------------------------------------------------
    // Validator management
    // -----------------------------------------------------------------------

    /// Register a validator address. In v2 single-node, call this once with
    /// the node's own address at startup.
    pub fn register_validator(&self, addr: Address) {
        let mut store = self.inner.write().unwrap();
        if !store.validators.contains(&addr) {
            store.validators.push(addr);
        }
    }

    /// Get the number of registered validators.
    pub fn validator_count(&self) -> usize {
        let store = self.inner.read().unwrap();
        store.validators.len()
    }

    /// Check if an address is a registered validator.
    pub fn is_validator(&self, addr: &Address) -> bool {
        let store = self.inner.read().unwrap();
        store.validators.contains(addr)
    }

    // -----------------------------------------------------------------------
    // Request creation (called by API_REQUEST precompile)
    // -----------------------------------------------------------------------

    /// Generate a deterministic request ID from block number and transaction index.
    /// The nonce handles multiple requests within the same transaction.
    pub fn generate_request_id(&self, block_number: u64, tx_index: u64) -> B256 {
        let nonce = self.request_nonce.fetch_add(1, Ordering::SeqCst);

        // Deterministic: same block + tx_index + nonce = same request_id
        let mut data = Vec::with_capacity(24);
        data.extend_from_slice(&block_number.to_be_bytes());
        data.extend_from_slice(&tx_index.to_be_bytes());
        data.extend_from_slice(&nonce.to_be_bytes());
        keccak256(&data)
    }

    /// Reset the nonce counter at the start of each block.
    /// Ensures deterministic ID generation across nodes.
    pub fn reset_nonce(&self) {
        self.request_nonce.store(0, Ordering::SeqCst);
    }

    /// Create a new pending request. Returns the request_id.
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

    // -----------------------------------------------------------------------
    // Validator submissions (called by ExternalDataService)
    // -----------------------------------------------------------------------

    /// Submit a value for a pending request.
    /// Returns Ok(()) if accepted, Err(reason) if rejected.
    pub fn submit_value(
        &self,
        request_id: B256,
        validator: Address,
        value: Vec<u8>,
        block_number: u64,
    ) -> Result<(), String> {
        let mut store = self.inner.write().unwrap();

        // Check request exists and is pending
        let request = store.pending.get(&request_id)
            .ok_or("Request not found")?;

        if request.status != RequestStatus::Pending {
            return Err(format!("Request not pending, status: {:?}", request.status));
        }

        // Check submission window hasn't closed
        if block_number > request.block_created + SUBMISSION_WINDOW {
            return Err("Submission window closed".to_string());
        }

        // Check validator is registered
        if !store.validators.contains(&validator) {
            return Err("Not a registered validator".to_string());
        }

        // Check validator hasn't already submitted for this request
        let submissions = store.submissions.get(&request_id)
            .ok_or("Submissions list not found")?;

        if submissions.iter().any(|s| s.validator == validator) {
            return Err("Validator already submitted".to_string());
        }

        // Accept the submission
        let submission = ValidatorSubmission {
            request_id,
            validator,
            value,
            block_submitted: block_number,
        };

        store.submissions.get_mut(&request_id).unwrap().push(submission);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Finalization (called by ExternalDataService after submission window)
    // -----------------------------------------------------------------------

    /// Get all pending requests that are ready for finalization
    /// (submission window has closed).
    pub fn get_requests_ready_to_finalize(&self, current_block: u64) -> Vec<PendingRequest> {
        let store = self.inner.read().unwrap();
        store.pending.values()
            .filter(|r| {
                r.status == RequestStatus::Pending
                    && current_block > r.block_created + SUBMISSION_WINDOW
            })
            .cloned()
            .collect()
    }

    /// Get all pending requests that need fetching (status == Pending,
    /// still within submission window).
    pub fn get_pending_requests(&self, current_block: u64) -> Vec<PendingRequest> {
        let store = self.inner.read().unwrap();
        store.pending.values()
            .filter(|r| {
                r.status == RequestStatus::Pending
                    && current_block <= r.block_created + SUBMISSION_WINDOW
            })
            .cloned()
            .collect()
    }

    /// Get submissions for a specific request.
    pub fn get_submissions(&self, request_id: &B256) -> Vec<ValidatorSubmission> {
        let store = self.inner.read().unwrap();
        store.submissions.get(request_id).cloned().unwrap_or_default()
    }

    /// Finalize a request with the aggregated result.
    pub fn finalize_request(
        &self,
        request_id: B256,
        value: Vec<u8>,
        num_submissions: u32,
        block_number: u64,
    ) -> Result<(), String> {
        let mut store = self.inner.write().unwrap();

        // Update request status
        let request = store.pending.get_mut(&request_id)
            .ok_or("Request not found")?;
        request.status = RequestStatus::Finalized;

        // Store the finalized result
        let result = FinalizedResult {
            request_id,
            value,
            num_submissions,
            finalized_at_block: block_number,
        };
        store.finalized.insert(request_id, result);

        Ok(())
    }

    /// Mark a request as timed out (not enough submissions).
    pub fn timeout_request(&self, request_id: B256) -> Result<(), String> {
        let mut store = self.inner.write().unwrap();
        let request = store.pending.get_mut(&request_id)
            .ok_or("Request not found")?;
        request.status = RequestStatus::TimedOut;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Reading results (called by API_READ precompile)
    // -----------------------------------------------------------------------

    /// Get the finalized result for a request, if available.
    pub fn get_finalized_result(&self, request_id: &B256) -> Option<FinalizedResult> {
        let store = self.inner.read().unwrap();
        store.finalized.get(request_id).cloned()
    }

    /// Get the status of a request.
    pub fn get_request_status(&self, request_id: &B256) -> Option<RequestStatus> {
        let store = self.inner.read().unwrap();
        store.pending.get(request_id).map(|r| r.status.clone())
    }

    /// Get a pending request by ID (needed by ExternalDataService to know
    /// what URL to fetch).
    pub fn get_request(&self, request_id: &B256) -> Option<PendingRequest> {
        let store = self.inner.read().unwrap();
        store.pending.get(request_id).cloned()
    }

    // -----------------------------------------------------------------------
    // Cleanup
    // -----------------------------------------------------------------------

    /// Clean up old finalized/timed-out requests older than `max_age` blocks.
    /// Prevents unbounded memory growth.
    pub fn cleanup(&self, current_block: u64, max_age: u64) {
        let mut store = self.inner.write().unwrap();

        // Collect request_ids to remove
        let to_remove: Vec<B256> = store.pending.iter()
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
// Median / Majority aggregation
// ---------------------------------------------------------------------------

/// Compute the median of a set of uint256 values.
/// Returns None if the input is empty.
pub fn compute_median_uint256(values: &mut Vec<U256>) -> Option<U256> {
    if values.is_empty() {
        return None;
    }

    values.sort();
    let len = values.len();

    if len % 2 == 0 {
        // Average of two middle values
        let a = values[len / 2 - 1];
        let b = values[len / 2];
        Some((a + b) / U256::from(2))
    } else {
        Some(values[len / 2])
    }
}

/// Compute majority vote for string values.
/// Returns the string that appears most often, if it has >50% of votes.
/// Returns None if no majority exists.
pub fn compute_majority_string(values: &[String]) -> Option<String> {
    if values.is_empty() {
        return None;
    }

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for v in values {
        *counts.entry(v.as_str()).or_insert(0) += 1;
    }

    let threshold = values.len() / 2;
    counts.into_iter()
        .filter(|(_, count)| *count > threshold)
        .max_by_key(|(_, count)| *count)
        .map(|(s, _)| s.to_string())
}

/// Compute majority vote for bool values.
/// Returns the bool that appears more than 50% of the time.
/// Returns None if exactly tied.
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
        None // exact tie
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

/// Global protocol store instance.
/// Accessible from precompiles and background services.
static GLOBAL_STORE: std::sync::LazyLock<ProtocolStore> =
    std::sync::LazyLock::new(|| ProtocolStore::new());

/// Get a reference to the global protocol store.
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
        store.register_validator(address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"));
        store.register_validator(address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"));
        store.register_validator(address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"));
        store
    }

    #[test]
    fn test_create_request_and_read() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);

        store.create_request(
            rid,
            100,
            "https://api.example.com/price".to_string(),
            "GET".to_string(),
            vec![],
            vec![],
            "price".to_string(),
            1,
        );

        let req = store.get_request(&rid).unwrap();
        assert_eq!(req.url, "https://api.example.com/price");
        assert_eq!(req.status, RequestStatus::Pending);
    }

    #[test]
    fn test_submit_and_finalize() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);
        let v1 = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let v2 = address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");

        store.create_request(
            rid, 100,
            "https://api.example.com/price".to_string(),
            "GET".to_string(), vec![], vec![],
            "price".to_string(), 1,
        );

        // Submit from two validators
        store.submit_value(rid, v1, vec![1, 2, 3], 101).unwrap();
        store.submit_value(rid, v2, vec![4, 5, 6], 101).unwrap();

        let subs = store.get_submissions(&rid);
        assert_eq!(subs.len(), 2);

        // Finalize
        store.finalize_request(rid, vec![7, 8, 9], 2, 103).unwrap();

        let result = store.get_finalized_result(&rid).unwrap();
        assert_eq!(result.value, vec![7, 8, 9]);
        assert_eq!(result.num_submissions, 2);

        let status = store.get_request_status(&rid).unwrap();
        assert_eq!(status, RequestStatus::Finalized);
    }

    #[test]
    fn test_duplicate_submission_rejected() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);
        let v1 = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

        store.create_request(
            rid, 100,
            "https://api.example.com".to_string(),
            "GET".to_string(), vec![], vec![],
            "value".to_string(), 1,
        );

        store.submit_value(rid, v1, vec![1, 2], 100).unwrap();
        let err = store.submit_value(rid, v1, vec![3, 4], 101).unwrap_err();
        assert_eq!(err, "Validator already submitted");
    }

    #[test]
    fn test_submission_window_enforced() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);
        let v1 = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

        store.create_request(
            rid, 100,
            "https://api.example.com".to_string(),
            "GET".to_string(), vec![], vec![],
            "value".to_string(), 1,
        );

        // Block 103 is past the window (created at 100, window = 2, so max = 102)
        let err = store.submit_value(rid, v1, vec![1, 2], 103).unwrap_err();
        assert_eq!(err, "Submission window closed");
    }

    #[test]
    fn test_unregistered_validator_rejected() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);
        let unknown = address!("0xdead000000000000000000000000000000000000");

        store.create_request(
            rid, 100,
            "https://api.example.com".to_string(),
            "GET".to_string(), vec![], vec![],
            "value".to_string(), 1,
        );

        let err = store.submit_value(rid, unknown, vec![1, 2], 100).unwrap_err();
        assert_eq!(err, "Not a registered validator");
    }

    #[test]
    fn test_timeout() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);

        store.create_request(
            rid, 100,
            "https://api.example.com".to_string(),
            "GET".to_string(), vec![], vec![],
            "value".to_string(), 1,
        );

        store.timeout_request(rid).unwrap();
        assert_eq!(store.get_request_status(&rid).unwrap(), RequestStatus::TimedOut);
    }

    #[test]
    fn test_median_odd() {
        let mut vals = vec![U256::from(100), U256::from(300), U256::from(200)];
        assert_eq!(compute_median_uint256(&mut vals), Some(U256::from(200)));
    }

    #[test]
    fn test_median_even() {
        let mut vals = vec![
            U256::from(100), U256::from(200),
            U256::from(300), U256::from(400),
        ];
        assert_eq!(compute_median_uint256(&mut vals), Some(U256::from(250)));
    }

    #[test]
    fn test_median_single_liar() {
        // 2 honest (104230, 104232), 1 liar (999999999)
        let mut vals = vec![
            U256::from(104230),
            U256::from(999999999),
            U256::from(104232),
        ];
        // Median should be 104232 — the liar can't move it
        assert_eq!(compute_median_uint256(&mut vals), Some(U256::from(104232)));
    }

    #[test]
    fn test_majority_string() {
        let vals = vec!["sunny".to_string(), "sunny".to_string(), "cloudy".to_string()];
        assert_eq!(compute_majority_string(&vals), Some("sunny".to_string()));
    }

    #[test]
    fn test_majority_string_no_majority() {
        let vals = vec!["sunny".to_string(), "cloudy".to_string(), "rainy".to_string()];
        assert_eq!(compute_majority_string(&vals), None);
    }

    #[test]
    fn test_majority_bool() {
        let vals = vec![true, true, false];
        assert_eq!(compute_majority_bool(&vals), Some(true));
    }

    #[test]
    fn test_cleanup() {
        let store = test_store();
        let rid = store.generate_request_id(100, 0);

        store.create_request(
            rid, 100,
            "https://api.example.com".to_string(),
            "GET".to_string(), vec![], vec![],
            "value".to_string(), 1,
        );

        store.finalize_request(rid, vec![1, 2, 3], 1, 103).unwrap();

        // Not old enough to clean (max_age = 50, current = 140)
        store.cleanup(140, 50);
        assert!(store.get_request(&rid).is_some());

        // Old enough to clean (max_age = 50, current = 200)
        store.cleanup(200, 50);
        assert!(store.get_request(&rid).is_none());
        assert!(store.get_finalized_result(&rid).is_none());
    }

    #[test]
    fn test_deterministic_request_ids() {
        let store = ProtocolStore::new();
        store.reset_nonce();

        let id1 = store.generate_request_id(100, 0);
        let id2 = store.generate_request_id(100, 1);

        // Different tx_index = different id
        assert_ne!(id1, id2);

        // Same inputs should give different ids (nonce increments)
        let id3 = store.generate_request_id(100, 0);
        assert_ne!(id1, id3); // nonce was 0 for id1, now it's 2 for id3
    }

    #[test]
    fn test_get_pending_and_ready_to_finalize() {
        let store = test_store();
        let rid1 = store.generate_request_id(100, 0);
        let rid2 = store.generate_request_id(105, 0);

        store.create_request(
            rid1, 100,
            "https://api.example.com/a".to_string(),
            "GET".to_string(), vec![], vec![],
            "a".to_string(), 1,
        );
        store.create_request(
            rid2, 105,
            "https://api.example.com/b".to_string(),
            "GET".to_string(), vec![], vec![],
            "b".to_string(), 1,
        );

        // At block 103: rid1 window closed (100+2=102), rid2 still open (105+2=107)
        let ready = store.get_requests_ready_to_finalize(103);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].request_id, rid1);

        let pending = store.get_pending_requests(103);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, rid2);
    }
}