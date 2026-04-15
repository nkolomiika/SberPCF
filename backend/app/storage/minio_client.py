from io import BytesIO
from uuid import uuid4

from minio import Minio

from app.config import get_settings

settings = get_settings()


class MinioStorage:
    """Обёртка над MinIO для загрузки и чтения файлов."""

    def __init__(self) -> None:
        self.client = Minio(
            endpoint=settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_use_ssl,
        )
        self.bucket = settings.minio_bucket_name

    def ensure_bucket(self) -> None:
        """Создаёт бакет, если он отсутствует."""
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)

    def upload_bytes(self, content: bytes, content_type: str, original_name: str) -> str:
        """Загружает файл в MinIO и возвращает ключ объекта."""
        key = f"{uuid4()}-{original_name}"
        self.client.put_object(
            bucket_name=self.bucket,
            object_name=key,
            data=BytesIO(content),
            length=len(content),
            content_type=content_type,
        )
        return key

    def download_bytes(self, object_key: str) -> bytes:
        """Скачивает файл по ключу объекта."""
        response = self.client.get_object(self.bucket, object_key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def delete(self, object_key: str) -> None:
        """Удаляет объект из MinIO."""
        self.client.remove_object(self.bucket, object_key)
