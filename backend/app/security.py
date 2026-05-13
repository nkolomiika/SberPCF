import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import get_settings
from app.exceptions import UnauthorizedError

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
settings = get_settings()


def hash_password(password: str) -> str:
    """Хэширует пароль пользователя с использованием bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет соответствие пароля его bcrypt-хэшу."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_refresh_token(token: str) -> str:
    """Возвращает SHA-256 хэш refresh-токена."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_agent_token(token: str) -> str:
    """Возвращает SHA-256 хэш agent API token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _encode_token(subject: UUID, token_type: str, expires_delta: timedelta) -> str:
    expire_at = datetime.now(UTC) + expires_delta
    payload = {
        "sub": str(subject),
        "type": token_type,
        "exp": int(expire_at.timestamp()),
        "iat": int(datetime.now(UTC).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")


def create_access_token(user_id: UUID) -> str:
    """Генерирует короткоживущий access-токен."""
    return _encode_token(user_id, "access", timedelta(minutes=settings.jwt_access_token_expire_minutes))


def create_refresh_token(user_id: UUID) -> str:
    """Генерирует долгоживущий refresh-токен."""
    return _encode_token(user_id, "refresh", timedelta(days=settings.jwt_refresh_token_expire_days))


def decode_token(token: str, expected_type: str) -> UUID:
    """Декодирует JWT и проверяет тип токена."""
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        if payload.get("type") != expected_type:
            raise UnauthorizedError("Некорректный тип токена")
        sub = payload.get("sub")
        if not sub:
            raise UnauthorizedError("В токене отсутствует sub")
        return UUID(sub)
    except (JWTError, ValueError) as exc:
        raise UnauthorizedError("Токен недействителен или истёк") from exc
