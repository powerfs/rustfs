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
use crate::storage_api_contracts::multipart::{
    CompletePart, ListMultipartsInfo, ListPartsInfo, MultipartInfo, MultipartUploadResult, PartInfo,
};
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

    /// 服务端复制。`src_info` 由 S3 层按 COPY/REPLACE 指令合并好最终元数据，
    /// 后端据此落盘目标对象；数据是否搬运由后端自行决定。
    #[allow(clippy::too_many_arguments)] // 参数个数由 S3 copy 契约决定
    async fn copy_object(
        &self,
        src_bucket: &str,
        src_object: &str,
        dst_bucket: &str,
        dst_object: &str,
        src_info: &mut ObjectInfo,
        src_opts: &ObjectOptions,
        dst_opts: &ObjectOptions,
    ) -> Result<ObjectInfo>;

    /// 仅合并元数据（对象锁 legal hold / retention 的 eval_metadata），不动数据。
    async fn put_object_metadata(&self, bucket: &str, object: &str, opts: &ObjectOptions) -> Result<ObjectInfo>;

    async fn get_object_tags(&self, bucket: &str, object: &str, opts: &ObjectOptions) -> Result<String>;

    async fn put_object_tags(&self, bucket: &str, object: &str, tags: &str, opts: &ObjectOptions) -> Result<ObjectInfo>;

    async fn delete_object_tags(&self, bucket: &str, object: &str, opts: &ObjectOptions) -> Result<ObjectInfo>;

    #[allow(clippy::too_many_arguments)] // 与 native list_objects_v2 签名保持一致
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

    // --- Multipart -------------------------------------------------------
    //
    // UploadPartCopy 不在此契约内：上游 `copy_object_part` 本身返回
    // NotImplemented，S3 层用「读源 + put_object_part」自行实现。

    async fn new_multipart_upload(&self, bucket: &str, object: &str, opts: &ObjectOptions) -> Result<MultipartUploadResult>;

    async fn put_object_part(
        &self,
        bucket: &str,
        object: &str,
        upload_id: &str,
        part_id: usize,
        data: &mut PutObjReader,
        opts: &ObjectOptions,
    ) -> Result<PartInfo>;

    async fn get_multipart_info(
        &self,
        bucket: &str,
        object: &str,
        upload_id: &str,
        opts: &ObjectOptions,
    ) -> Result<MultipartInfo>;

    #[allow(clippy::too_many_arguments)] // 与 native list_object_parts 签名保持一致
    async fn list_object_parts(
        &self,
        bucket: &str,
        object: &str,
        upload_id: &str,
        part_number_marker: Option<usize>,
        max_parts: usize,
        opts: &ObjectOptions,
    ) -> Result<ListPartsInfo>;

    async fn abort_multipart_upload(&self, bucket: &str, object: &str, upload_id: &str, opts: &ObjectOptions) -> Result<()>;

    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        object: &str,
        upload_id: &str,
        uploaded_parts: Vec<CompletePart>,
        opts: &ObjectOptions,
    ) -> Result<ObjectInfo>;

    #[allow(clippy::too_many_arguments)] // 与 native list_multipart_uploads 签名保持一致
    async fn list_multipart_uploads(
        &self,
        bucket: &str,
        prefix: &str,
        key_marker: Option<String>,
        upload_id_marker: Option<String>,
        delimiter: Option<String>,
        max_uploads: usize,
    ) -> Result<ListMultipartsInfo>;
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

/// 系统保留桶（配置、IAM、扫描器状态等）始终留在控制面原生 ECStore 上。
///
/// powerfs 模式下外部后端接管用户桶；这些系统桶在启动阶段就要读写
/// （`config/config.json`、`iam/` 等），如果一并委托，外部存储里没有
/// 对应桶就会导致 IAM 初始化卡住、S3 一直返回 503。
pub fn is_control_plane_bucket(bucket: &str) -> bool {
    bucket == crate::disk::RUSTFS_META_BUCKET || bucket == crate::disk::MIGRATING_META_BUCKET
}

/// 返回可承接该桶的外部后端；系统桶返回 `None`，走原生 ECStore 路径。
pub fn backend_for_bucket(bucket: &str) -> Option<&'static Arc<dyn ExternalBackend>> {
    if is_control_plane_bucket(bucket) {
        return None;
    }
    backend()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug)]
    struct StubBackend {
        buckets: std::sync::Mutex<Vec<String>>,
        objects: std::sync::Mutex<Vec<(String, usize)>>,
        tags: std::sync::Mutex<std::collections::HashMap<(String, String), String>>,
        parts: std::sync::Mutex<std::collections::HashMap<(String, usize), usize>>,
        next_upload_id: AtomicUsize,
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

        async fn copy_object(
            &self,
            src_bucket: &str,
            src_object: &str,
            dst_bucket: &str,
            dst_object: &str,
            _src_info: &mut ObjectInfo,
            _src_opts: &ObjectOptions,
            _dst_opts: &ObjectOptions,
        ) -> Result<ObjectInfo> {
            let buckets = self.buckets.lock().unwrap();
            if !buckets.iter().any(|b| b == src_bucket) {
                return Err(crate::error::Error::BucketNotFound(src_bucket.to_string()));
            }
            if !buckets.iter().any(|b| b == dst_bucket) {
                return Err(crate::error::Error::BucketNotFound(dst_bucket.to_string()));
            }
            drop(buckets);
            if !self.objects.lock().unwrap().iter().any(|(k, _)| k == src_object) {
                return Err(crate::error::Error::FileNotFound);
            }
            self.objects.lock().unwrap().push((dst_object.to_string(), 0));
            Ok(ObjectInfo::default())
        }

        async fn put_object_metadata(&self, bucket: &str, object: &str, _opts: &ObjectOptions) -> Result<ObjectInfo> {
            self.get_object_info(bucket, object, &ObjectOptions::default()).await
        }

        async fn get_object_tags(&self, bucket: &str, object: &str, _opts: &ObjectOptions) -> Result<String> {
            Ok(self
                .tags
                .lock()
                .unwrap()
                .get(&(bucket.to_string(), object.to_string()))
                .cloned()
                .unwrap_or_default())
        }

        async fn put_object_tags(&self, bucket: &str, object: &str, tags: &str, _opts: &ObjectOptions) -> Result<ObjectInfo> {
            self.tags
                .lock()
                .unwrap()
                .insert((bucket.to_string(), object.to_string()), tags.to_string());
            Ok(ObjectInfo::default())
        }

        async fn delete_object_tags(&self, bucket: &str, object: &str, _opts: &ObjectOptions) -> Result<ObjectInfo> {
            self.tags.lock().unwrap().remove(&(bucket.to_string(), object.to_string()));
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

        async fn new_multipart_upload(
            &self,
            _bucket: &str,
            _object: &str,
            _opts: &ObjectOptions,
        ) -> Result<MultipartUploadResult> {
            let id = self.next_upload_id.fetch_add(1, Ordering::SeqCst).to_string();
            Ok(MultipartUploadResult {
                upload_id: id,
                checksum_algo: None,
                checksum_type: None,
            })
        }

        async fn put_object_part(
            &self,
            _bucket: &str,
            _object: &str,
            upload_id: &str,
            part_id: usize,
            _data: &mut PutObjReader,
            _opts: &ObjectOptions,
        ) -> Result<PartInfo> {
            self.parts.lock().unwrap().insert((upload_id.to_string(), part_id), 0);
            Ok(PartInfo {
                part_num: part_id,
                ..PartInfo::default()
            })
        }

        async fn get_multipart_info(
            &self,
            bucket: &str,
            object: &str,
            upload_id: &str,
            _opts: &ObjectOptions,
        ) -> Result<MultipartInfo> {
            Ok(MultipartInfo {
                bucket: bucket.to_string(),
                object: object.to_string(),
                upload_id: upload_id.to_string(),
                ..MultipartInfo::default()
            })
        }

        async fn list_object_parts(
            &self,
            bucket: &str,
            object: &str,
            upload_id: &str,
            _part_number_marker: Option<usize>,
            _max_parts: usize,
            _opts: &ObjectOptions,
        ) -> Result<ListPartsInfo> {
            let parts = self
                .parts
                .lock()
                .unwrap()
                .iter()
                .filter(|((id, _), _)| id == upload_id)
                .map(|((_, number), _)| PartInfo {
                    part_num: *number,
                    ..PartInfo::default()
                })
                .collect();
            Ok(ListPartsInfo {
                bucket: bucket.to_string(),
                object: object.to_string(),
                upload_id: upload_id.to_string(),
                parts,
                ..ListPartsInfo::default()
            })
        }

        async fn abort_multipart_upload(
            &self,
            _bucket: &str,
            _object: &str,
            upload_id: &str,
            _opts: &ObjectOptions,
        ) -> Result<()> {
            self.parts.lock().unwrap().retain(|(id, _), _| id != upload_id);
            Ok(())
        }

        async fn complete_multipart_upload(
            &self,
            _bucket: &str,
            _object: &str,
            upload_id: &str,
            uploaded_parts: Vec<CompletePart>,
            _opts: &ObjectOptions,
        ) -> Result<ObjectInfo> {
            if !self.parts.lock().unwrap().iter().any(|((id, _), _)| id == upload_id) {
                return Err(crate::error::Error::InvalidUploadID(upload_id.to_string(), String::new(), String::new()));
            }
            if uploaded_parts.is_empty() {
                return Err(crate::error::Error::InvalidPart(0, String::new(), String::new()));
            }
            // 完成即销毁会话（与真实后端一致），重放同一 upload_id 应失败。
            self.parts.lock().unwrap().retain(|(id, _), _| id != upload_id);
            Ok(ObjectInfo::default())
        }

        async fn list_multipart_uploads(
            &self,
            _bucket: &str,
            _prefix: &str,
            key_marker: Option<String>,
            upload_id_marker: Option<String>,
            delimiter: Option<String>,
            max_uploads: usize,
        ) -> Result<ListMultipartsInfo> {
            Ok(ListMultipartsInfo {
                key_marker,
                upload_id_marker,
                max_uploads,
                delimiter,
                ..ListMultipartsInfo::default()
            })
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
    fn control_plane_buckets_stay_native() {
        assert!(is_control_plane_bucket(crate::disk::RUSTFS_META_BUCKET));
        assert!(is_control_plane_bucket(crate::disk::MIGRATING_META_BUCKET));
        assert!(!is_control_plane_bucket("user-bucket"));
        // 未安装后端时，任何桶都不会被委托。
        assert!(backend_for_bucket("user-bucket").is_none());
    }

    #[test]
    fn stub_backend_serves_bucket_contract() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let stub: Arc<dyn ExternalBackend> = Arc::new(StubBackend {
                buckets: std::sync::Mutex::new(Vec::new()),
                objects: std::sync::Mutex::new(Vec::new()),
                tags: std::sync::Mutex::new(std::collections::HashMap::new()),
                parts: std::sync::Mutex::new(std::collections::HashMap::new()),
                next_upload_id: AtomicUsize::new(1),
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

            // copy / tagging 契约 round-trip。
            stub.put_object("beta", "src", &mut PutObjReader::from_vec(Vec::new()), &ObjectOptions::default())
                .await
                .unwrap();
            // 源对象不存在 → FileNotFound；目标桶不存在 → BucketNotFound。
            stub.copy_object(
                "beta",
                "missing",
                "beta",
                "dst",
                &mut ObjectInfo::default(),
                &ObjectOptions::default(),
                &ObjectOptions::default(),
            )
            .await
            .unwrap_err();
            stub.copy_object(
                "beta",
                "src",
                "gamma",
                "dst",
                &mut ObjectInfo::default(),
                &ObjectOptions::default(),
                &ObjectOptions::default(),
            )
            .await
            .unwrap_err();
            stub.copy_object(
                "beta",
                "src",
                "beta",
                "dst",
                &mut ObjectInfo::default(),
                &ObjectOptions::default(),
                &ObjectOptions::default(),
            )
            .await
            .unwrap();
            assert!(stub.get_object_info("beta", "dst", &ObjectOptions::default()).await.is_ok());

            stub.put_object_tags("beta", "dst", "k1=v1", &ObjectOptions::default())
                .await
                .unwrap();
            assert_eq!(stub.get_object_tags("beta", "dst", &ObjectOptions::default()).await.unwrap(), "k1=v1");
            stub.delete_object_tags("beta", "dst", &ObjectOptions::default())
                .await
                .unwrap();
            assert_eq!(stub.get_object_tags("beta", "dst", &ObjectOptions::default()).await.unwrap(), "");

            // multipart 契约 round-trip：创建会话 → 上传分块 → 列举 → 完成 / 中止。
            let upload = stub
                .new_multipart_upload("beta", "mp", &ObjectOptions::default())
                .await
                .unwrap();
            assert!(!upload.upload_id.is_empty());
            assert!(
                stub.get_multipart_info("beta", "mp", &upload.upload_id, &ObjectOptions::default())
                    .await
                    .is_ok()
            );
            stub.put_object_part(
                "beta",
                "mp",
                &upload.upload_id,
                1,
                &mut PutObjReader::from_vec(Vec::new()),
                &ObjectOptions::default(),
            )
            .await
            .unwrap();
            let listed = stub
                .list_object_parts("beta", "mp", &upload.upload_id, None, 1000, &ObjectOptions::default())
                .await
                .unwrap();
            assert_eq!(listed.parts.len(), 1);
            let completed = stub
                .complete_multipart_upload(
                    "beta",
                    "mp",
                    &upload.upload_id,
                    vec![CompletePart {
                        part_num: 1,
                        ..CompletePart::default()
                    }],
                    &ObjectOptions::default(),
                )
                .await
                .unwrap();
            assert_eq!(completed.size, 0);
            // 完成后再完成同一会话 → InvalidUploadID（分块已被清理语义）。
            assert!(
                stub.complete_multipart_upload(
                    "beta",
                    "mp",
                    &upload.upload_id,
                    vec![CompletePart {
                        part_num: 1,
                        ..CompletePart::default()
                    }],
                    &ObjectOptions::default(),
                )
                .await
                .is_err()
            );
            // 无分块会话的 abort 不报错。
            let second = stub
                .new_multipart_upload("beta", "mp2", &ObjectOptions::default())
                .await
                .unwrap();
            stub.abort_multipart_upload("beta", "mp2", &second.upload_id, &ObjectOptions::default())
                .await
                .unwrap();
            let listing = stub.list_multipart_uploads("beta", "", None, None, None, 1000).await.unwrap();
            assert!(!listing.is_truncated);
        });
    }
}
