import pytest
from pydantic import ValidationError as PydanticValidationError

from app.schemas import (
    EndpointCreate,
    HostCreate,
    PortCreate,
    UserCreate,
    VulnerabilityCreate,
    VulnerabilityStatusPatch,
)


def test_user_create_rejects_short_password_tc_usr_008() -> None:
    with pytest.raises(PydanticValidationError):
        UserCreate(
            username="new_user",
            email="new_user@example.com",
            password="short",
        )


def test_host_create_requires_ip_or_hostname_tc_host_003() -> None:
    with pytest.raises(PydanticValidationError):
        HostCreate(os="Ubuntu 22.04")


def test_host_create_accepts_hostname_only_tc_host_002() -> None:
    payload = HostCreate(hostname="target.example.com")

    assert payload.hostname == "target.example.com"
    assert payload.ip_address is None


@pytest.mark.parametrize("port", [1, 65535])
def test_port_create_accepts_boundary_values_tc_port_003_004(port: int) -> None:
    payload = PortCreate(port_number=port)

    assert payload.port_number == port


@pytest.mark.parametrize("port", [0, 65536])
def test_port_create_rejects_out_of_range_values_tc_port_005_006(port: int) -> None:
    with pytest.raises(PydanticValidationError):
        PortCreate(port_number=port)


def test_endpoint_requires_path_tc_ep_003() -> None:
    with pytest.raises(PydanticValidationError):
        EndpointCreate(method="GET")


def test_vulnerability_rejects_invalid_cvss_score_tc_vuln_005() -> None:
    with pytest.raises(PydanticValidationError):
        VulnerabilityCreate(
            title="CVSS overflow",
            severity="high",
            cvss_score=10.1,
        )


def test_vulnerability_rejects_invalid_status_patch_tc_vuln_010() -> None:
    with pytest.raises(PydanticValidationError):
        VulnerabilityStatusPatch(status="closed")
