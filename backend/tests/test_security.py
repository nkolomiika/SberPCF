from itertools import count as _id_count

_ids = _id_count(1)

import pytest

from app.exceptions import UnauthorizedError
from app.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_refresh_token,
)


def test_access_token_roundtrip_tc_auth_001() -> None:
    user_id = next(_ids)

    token = create_access_token(user_id)
    decoded_id = decode_token(token, expected_type="access")

    assert decoded_id == user_id


def test_refresh_token_roundtrip_tc_auth_006() -> None:
    user_id = next(_ids)

    token = create_refresh_token(user_id)
    decoded_id = decode_token(token, expected_type="refresh")

    assert decoded_id == user_id


def test_decode_token_rejects_wrong_type_tc_auth_010() -> None:
    token = create_refresh_token(next(_ids))

    with pytest.raises(UnauthorizedError, match="Некорректный тип токена"):
        decode_token(token, expected_type="access")


def test_hash_refresh_token_is_deterministic() -> None:
    token = "refresh-token-value"

    digest_1 = hash_refresh_token(token)
    digest_2 = hash_refresh_token(token)

    assert digest_1 == digest_2
    assert len(digest_1) == 64
