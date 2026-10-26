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
use http::HeaderMap;

use crate::error::Result;
use crate::object_api::{GetObjectReader, ObjectInfo, ObjectOptions, PutObjReader};
use crate::storage_api_contracts::bucket::{BucketInfo, BucketOptions, DeleteBucketOptions, MakeBucketOptions};
use crate::storage_api_contracts::list::{StorageListObjectVersionsInfo, StorageListObjectsV2Info};
use crate::storage_api_contracts::range::HTTPRangeSpec;

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

/// Storage operations served by the external backend.
///
/// Buckets and single-object read/write/list are covered here. Multipart and
/// namespace locking are added in later stages; EC-only operations (rebalance,
/// decommission, heal, scanner) are never routed here.
#[async_trait]
pub trait ExternalBackend: Send + Sync + std::fmt::Debug {
    async fn make_bucket(&self, bucket: &str, opts: &MakeBucketOptions) -> Result<()>;

    async fn get_bucket_info(&self, bucket: &str, opts: &BucketOptions) -> Result<BucketInfo>;

    async fn list_bucket(&self, opts: &BucketOptions) -> Result<Vec<BucketInfo>>;

    async fn delete_bucket(&self, bucket: &str, opts: &DeleteBucketOptions) -> Result<()>;

    async fn get_object_info(&self, bucket: &str, object: &str, opts: &ObjectOptions) -> Result<ObjectInfo>;

    async fn get_object_reader(
        &self,
        bucket: &str,
        object: &str,
        range: Option<HTTPRangeSpec>,
        h: HeaderMap,
        opts: &ObjectOptions,
    ) -> Result<GetObjectReader>;

    async fn put_object(&self, bucket: &str, object: &str, data: &mut PutObjReader, opts: &ObjectOptions) -> Result<ObjectInfo>;

    async fn delete_object(&self, bucket: &str, object: &str, opts: ObjectOptions) -> Result<ObjectInfo>;

    async fn list_objects_v2(
        &self,
        bucket: &str,
        prefix: &str,
        continuation_token: Option<String>,
        delimiter: Option<String>,
        max_keys: i32,
        fetch_owner: bool,
        start_after: Option<String>,
        incl_deleted: bool,
    ) -> Result<StorageListObjectsV2Info<ObjectInfo>>;

    async fn list_object_versions(
        &self,
        bucket: &str,
        prefix: &str,
        marker: Option<String>,
        version_marker: Option<String>,
        delimiter: Option<String>,
        max_keys: i32,
    ) -> Result<StorageListObjectVersionsInfo<ObjectInfo>>;
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
        objects: std::sync::Mutex<Vec<(String, usize)>>,
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

        async fn get_object_info(&self, bucket: &str, object: &str, _opts: &ObjectOptions) -> Result<ObjectInfo> {
            let buckets = self.buckets.lock().unwrap();
            if !buckets.iter().any(|b| b == bucket) {
                return Err(crate::error::Error::BucketNotFound(bucket.to_string()));
            }
            if !self.objects.lock().unwrap().iter().any(|(k, _)| k == object) {
                return Err(crate::error::Error::FileNotFound);
            }
            Ok(ObjectInfo::default())
        }

        async fn get_object_reader(
            &self,
            _bucket: &str,
            _object: &str,
            _range: Option<HTTPRangeSpec>,
            _h: HeaderMap,
            _opts: &ObjectOptions,
        ) -> Result<GetObjectReader> {
            Err(crate::error::Error::NotImplemented)
        }

        async fn put_object(
            &self,
            bucket: &str,
            object: &str,
            _data: &mut PutObjReader,
            _opts: &ObjectOptions,
        ) -> Result<ObjectInfo> {
            let buckets = self.buckets.lock().unwrap();
            if !buckets.iter().any(|b| b == bucket) {
                return Err(crate::error::Error::BucketNotFound(bucket.to_string()));
            }
            self.objects.lock().unwrap().push((object.to_string(), 0));
            Ok(ObjectInfo::default())
        }

        async fn delete_object(&self, bucket: &str, object: &str, _opts: ObjectOptions) -> Result<ObjectInfo> {
            let buckets = self.buckets.lock().unwrap();
            if !buckets.iter().any(|b| b == bucket) {
                return Err(crate::error::Error::BucketNotFound(bucket.to_string()));
            }
            self.objects.lock().unwrap().retain(|(k, _)| k != object);
            Ok(ObjectInfo::default())
        }

        async fn list_objects_v2(
            &self,
            _bucket: &str,
            _prefix: &str,
            _continuation_token: Option<String>,
            _delimiter: Option<String>,
            _max_keys: i32,
            _fetch_owner: bool,
            _start_after: Option<String>,
            _incl_deleted: bool,
        ) -> Result<StorageListObjectsV2Info<ObjectInfo>> {
            Err(crate::error::Error::NotImplemented)
        }

        async fn list_object_versions(
            &self,
            _bucket: &str,
            _prefix: &str,
            _marker: Option<String>,
            _version_marker: Option<String>,
            _delimiter: Option<String>,
            _max_keys: i32,
        ) -> Result<StorageListObjectVersionsInfo<ObjectInfo>> {
            Err(crate::error::Error::NotImplemented)
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
                objects: std::sync::Mutex::new(Vec::new()),
                puts: AtomicUsize::new(0),
            });
            stub.make_bucket("alpha", &MakeBucketOptions::default()).await.unwrap();
            stub.make_bucket("beta", &MakeBucketOptions::default()).await.unwrap();
            assert!(stub.get_bucket_info("alpha", &BucketOptions::default()).await.is_ok());
            assert!(stub.get_bucket_info("gamma", &BucketOptions::default()).await.is_err());
            assert_eq!(stub.list_bucket(&BucketOptions::default()).await.unwrap().len(), 2);
            stub.delete_bucket("alpha", &DeleteBucketOptions::default()).await.unwrap();
            assert!(stub.get_bucket_info("alpha", &BucketOptions::default()).await.is_err());

            // Object path: bucket must exist, then put/get/delete round-trip.
            assert!(stub.get_object_info("beta", "k1", &ObjectOptions::default()).await.is_err());
            assert!(
                stub.put_object("gamma", "k1", &mut PutObjReader::from_vec(Vec::new()), &ObjectOptions::default())
                    .await
                    .is_err()
            );
            let mut reader = PutObjReader::from_vec(Vec::new());
            stub.put_object("beta", "k1", &mut reader, &ObjectOptions::default())
                .await
                .unwrap();
            assert!(stub.get_object_info("beta", "k1", &ObjectOptions::default()).await.is_ok());
            stub.delete_object("beta", "k1", ObjectOptions::default()).await.unwrap();
            assert!(stub.get_object_info("beta", "k1", &ObjectOptions::default()).await.is_err());
        });
    }
}
