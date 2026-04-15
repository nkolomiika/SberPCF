import os
import datetime


REQUIRED_TEST_ENV = {
    "DATABASE_URL": "postgresql+asyncpg://user:password@localhost:5432/pcf_test",
    "JWT_SECRET_KEY": "test_secret_key_that_has_minimum_length_32_chars",
    "MINIO_ENDPOINT": "localhost:9000",
    "MINIO_ACCESS_KEY": "minioadmin",
    "MINIO_SECRET_KEY": "minioadmin",
    "MINIO_BUCKET_NAME": "pcf-files-test",
    "CSRF_ALLOWED_ORIGINS": "http://localhost:3000,http://frontend.local",
}


for key, value in REQUIRED_TEST_ENV.items():
    os.environ.setdefault(key, value)

if not hasattr(datetime, "UTC"):
    datetime.UTC = datetime.timezone.utc  # type: ignore[attr-defined]
