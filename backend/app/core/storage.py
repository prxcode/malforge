"""
MAP — Object Storage (MinIO)

Abstraction layer for file storage using MinIO S3-compatible storage.
Falls back to local filesystem if MinIO is unavailable.
"""

import io
import os
import hashlib
import structlog
from typing import Optional

from minio import Minio
from minio.error import S3Error

from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


class StorageService:
    """MinIO-backed object storage with local filesystem fallback."""

    def __init__(self):
        self._client: Optional[Minio] = None
        self._bucket = settings.minio_bucket_samples
        self._local_path = settings.storage_path
        self._initialized = False

    def _get_client(self) -> Minio:
        """Lazy-initialize the MinIO client."""
        if self._client is None:
            self._client = Minio(
                settings.minio_endpoint,
                access_key=settings.minio_root_user,
                secret_key=settings.minio_root_password,
                secure=settings.minio_use_ssl,
            )
        return self._client

    async def initialize(self) -> bool:
        """
        Ensure the storage bucket exists.
        Returns True if MinIO is available, False if falling back to local.
        """
        try:
            client = self._get_client()
            if not client.bucket_exists(self._bucket):
                client.make_bucket(self._bucket)
                logger.info("Created MinIO bucket", bucket=self._bucket)
            self._initialized = True
            logger.info("MinIO storage initialized", bucket=self._bucket)
            return True
        except Exception as e:
            logger.warning(
                "MinIO unavailable, using local filesystem fallback",
                error=str(e),
            )
            os.makedirs(self._local_path, exist_ok=True)
            self._initialized = False
            return False

    def _get_object_path(self, sha256: str, filename: str) -> str:
        """
        Generate storage path organized by hash prefix.
        Example: ab/cd/abcdef1234.../original_filename.exe
        """
        prefix = sha256[:2]
        subdir = sha256[2:4]
        return f"{prefix}/{subdir}/{sha256}/{filename}"

    async def save_file(
        self,
        file_data: bytes,
        sha256: str,
        filename: str,
        content_type: str = "application/octet-stream",
    ) -> str:
        """
        Save file to storage. Returns the object path/key.
        """
        object_path = self._get_object_path(sha256, filename)

        if self._initialized:
            try:
                client = self._get_client()
                data_stream = io.BytesIO(file_data)
                client.put_object(
                    self._bucket,
                    object_path,
                    data_stream,
                    length=len(file_data),
                    content_type=content_type,
                )
                logger.info("File saved to MinIO", path=object_path, size=len(file_data))
                return object_path
            except S3Error as e:
                logger.error("MinIO save failed, falling back to local", error=str(e))

        # Local fallback
        local_dir = os.path.join(self._local_path, sha256[:2], sha256[2:4], sha256)
        os.makedirs(local_dir, exist_ok=True)
        local_file = os.path.join(local_dir, filename)
        with open(local_file, "wb") as f:
            f.write(file_data)
        logger.info("File saved to local storage", path=local_file, size=len(file_data))
        return object_path

    async def get_file(self, sha256: str, filename: str) -> Optional[bytes]:
        """Retrieve file from storage."""
        object_path = self._get_object_path(sha256, filename)

        if self._initialized:
            try:
                client = self._get_client()
                response = client.get_object(self._bucket, object_path)
                data = response.read()
                response.close()
                response.release_conn()
                return data
            except S3Error as e:
                logger.error("MinIO get failed", path=object_path, error=str(e))

        # Local fallback
        local_dir = os.path.join(self._local_path, sha256[:2], sha256[2:4], sha256)
        local_file = os.path.join(local_dir, filename)
        if os.path.exists(local_file):
            with open(local_file, "rb") as f:
                return f.read()
        return None

    async def delete_file(self, sha256: str, filename: str) -> bool:
        """Delete file from storage."""
        object_path = self._get_object_path(sha256, filename)

        if self._initialized:
            try:
                client = self._get_client()
                client.remove_object(self._bucket, object_path)
                logger.info("File deleted from MinIO", path=object_path)
                return True
            except S3Error as e:
                logger.error("MinIO delete failed", path=object_path, error=str(e))
                return False

        # Local fallback
        local_dir = os.path.join(self._local_path, sha256[:2], sha256[2:4], sha256)
        local_file = os.path.join(local_dir, filename)
        if os.path.exists(local_file):
            os.remove(local_file)
            return True
        return False

    async def file_exists(self, sha256: str, filename: str) -> bool:
        """Check if file exists in storage."""
        object_path = self._get_object_path(sha256, filename)

        if self._initialized:
            try:
                client = self._get_client()
                client.stat_object(self._bucket, object_path)
                return True
            except S3Error:
                return False

        # Local fallback
        local_dir = os.path.join(self._local_path, sha256[:2], sha256[2:4], sha256)
        local_file = os.path.join(local_dir, filename)
        return os.path.exists(local_file)

    @staticmethod
    def compute_hashes(data: bytes) -> dict:
        """Compute SHA256, SHA1, and MD5 hashes for file data."""
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
        }

    @staticmethod
    def compute_entropy(data: bytes) -> float:
        """Compute Shannon entropy of file data."""
        if not data:
            return 0.0

        import math
        from collections import Counter

        byte_counts = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in byte_counts.values():
            if count == 0:
                continue
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)


# Singleton
storage_service = StorageService()
