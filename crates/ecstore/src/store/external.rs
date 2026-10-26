// PowerFS fork patch: external storage backend injection seam.
//
// Upstream RustFS is hard-wired to ECStore over local erasure-coded disks.
// This module adds a process-global optional backend so the same S3 surface,
// IAM and admin layers can run on top of an external storage engine (PowerFS
// needle/volume) without changing any call site outside `crates/ecstore`.
//
// Invariants:
// - When `install` is never called (`native` mode), `backend()` returns `None`
//   and the ECStore code path is byte-for-byte the upstream behaviour.
// - The backend is installed once during startup, before serving traffic.
// - Only the S3-facing contract methods are routed here; EC-only operations
//   (rebalance, decommission, heal, scanner) stay on ECStore and must report
//   `Unsupported` in powerfs mode.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;

use crate::error::Result;
use crate::storage_api_contracts::bucket::{BucketInfo, BucketOptions, DeleteBucketOptions, MakeBucketOptions};

/// Storage driver selected at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageDriver {
    /// Upstream behaviour: local erasure-coded disks.
    Native,
    /// External backend (PowerFS volume/needle).
    PowerFs,
}

impl StorageDriver {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageDriver::Native => "native",
            StorageDriver::PowerFs => "powerfs",
        }
    }
}

/// Bucket-level operations served by the external backend.
///
/// Object/multipart/list operations are added in later stages (P1b+); they are
/// intentionally absent here so each stage stays inside its patch budget.
#[async_trait]
pub trait ExternalBackend: Send + Sync + std::fmt::Debug {
    async fn make_bucket(&self, bucket: &str, opts: &MakeBucketOptions) -> Result<()>;

    async fn get_bucket_info(&self, bucket: &str, opts: &BucketOptions) -> Result<BucketInfo>;

    async fn list_bucket(&self, opts: &BucketOptions) -> Result<Vec<BucketInfo>>;

    async fn delete_bucket(&self, bucket: &str, opts: &DeleteBucketOptions) -> Result<()>;
}

static BACKEND: OnceLock<Arc<dyn ExternalBackend>> = OnceLock::new();
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Installs the external backend. Must be called at most once, before ECStore
/// serves any request.
///
/// Returns the rejected value if a backend was already installed.
pub fn install(backend: Arc<dyn ExternalBackend>) -> std::result::Result<(), Arc<dyn ExternalBackend>> {
    match BACKEND.set(backend) {
        Ok(()) => {
            INSTALLED.store(true, Ordering::Release);
            Ok(())
        }
        Err(rejected) => Err(rejected),
    }
}

/// Returns the installed backend, if any.
pub fn backend() -> Option<&'static Arc<dyn ExternalBackend>> {
    BACKEND.get()
}

/// True when an external backend is installed (powerfs mode).
pub fn is_enabled() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug)]
    struct StubBackend {
        buckets: std::sync::Mutex<Vec<String>>,
        puts: AtomicUsize,
    }

    #[async_trait]
    impl ExternalBackend for StubBackend {
        async fn make_bucket(&self, bucket: &str, _opts: &MakeBucketOptions) -> Result<()> {
            self.puts.fetch_add(1, Ordering::SeqCst);
            self.buckets.lock().unwrap().push(bucket.to_string());
            Ok(())
        }

        async fn get_bucket_info(&self, bucket: &str, _opts: &BucketOptions) -> Result<BucketInfo> {
            let buckets = self.buckets.lock().unwrap();
            if buckets.iter().any(|b| b == bucket) {
                Ok(BucketInfo::default())
            } else {
                Err(crate::error::Error::BucketNotFound(bucket.to_string()))
            }
        }

        async fn list_bucket(&self, _opts: &BucketOptions) -> Result<Vec<BucketInfo>> {
            let buckets = self.buckets.lock().unwrap();
            Ok(buckets.iter().map(|_| BucketInfo::default()).collect())
        }

        async fn delete_bucket(&self, bucket: &str, _opts: &DeleteBucketOptions) -> Result<()> {
            let mut buckets = self.buckets.lock().unwrap();
            buckets.retain(|b| b != bucket);
            Ok(())
        }
    }

    #[test]
    fn native_mode_has_no_backend() {
        assert!(!is_enabled());
        assert!(backend().is_none());
    }

    #[test]
    fn driver_names_stable() {
        assert_eq!(StorageDriver::Native.as_str(), "native");
        assert_eq!(StorageDriver::PowerFs.as_str(), "powerfs");
    }

    #[test]
    fn stub_backend_serves_bucket_contract() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let stub: Arc<dyn ExternalBackend> = Arc::new(StubBackend {
                buckets: std::sync::Mutex::new(Vec::new()),
                puts: AtomicUsize::new(0),
            });
            stub.make_bucket("alpha", &MakeBucketOptions::default()).await.unwrap();
            stub.make_bucket("beta", &MakeBucketOptions::default()).await.unwrap();
            assert!(stub.get_bucket_info("alpha", &BucketOptions::default()).await.is_ok());
            assert!(stub.get_bucket_info("gamma", &BucketOptions::default()).await.is_err());
            assert_eq!(stub.list_bucket(&BucketOptions::default()).await.unwrap().len(), 2);
            stub.delete_bucket("alpha", &DeleteBucketOptions::default()).await.unwrap();
            assert!(stub.get_bucket_info("alpha", &BucketOptions::default()).await.is_err());
        });
    }
}
