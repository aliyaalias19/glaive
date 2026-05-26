"""Tests for the typed node subclasses in glaive/graph/nodes.py.

One test class per node type. Tests verify:
  - canonical_key() returns the schema-section-5 identity tuple
  - merge_into() implements the schema-section-5 merge rule
  - Type-specific validation works (e.g., required fields)

Reference: docs/EVIDENCE_GRAPH_SCHEMA.md section 2 (per-node) and section 5 (merge rules).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from glaive.graph.nodes import File, Host, NetworkEndpoint, RegistryKey, User


VALID_HASH = "a" * 64
GUID_RD01 = "12345678-1234-1234-1234-1234567890ab"
GUID_DC01 = "abcdef01-abcd-abcd-abcd-abcdef012345"


# =============================================================================
# Host
# =============================================================================


class TestHost:
    """Schema section 2.1 — Host node."""

    # ---- construction ----

    def test_minimal_construction(self) -> None:
        """A Host needs only the universal three + hostname."""
        h = Host(evidence_hash=VALID_HASH, derivation="recmd SYSTEM", hostname="rd01")
        assert h.hostname == "rd01"
        assert h.machine_guid is None
        assert h.os_version is None
        assert h.timezone == "UTC"
        assert h.network_subnet is None

    def test_full_construction(self) -> None:
        h = Host(
            evidence_hash=VALID_HASH,
            derivation="recmd SYSTEM",
            hostname="rd01",
            machine_guid=GUID_RD01,
            os_version="Windows Server 2022",
            timezone="UTC",
            network_subnet="172.16.6.0/24",
        )
        assert h.machine_guid == GUID_RD01

    def test_hostname_required(self) -> None:
        """hostname is the one mandatory non-provenance field."""
        with pytest.raises(ValidationError):
            Host(evidence_hash=VALID_HASH, derivation="recmd SYSTEM")  # type: ignore[call-arg]

    # ---- canonical_key ----

    def test_canonical_key_prefers_machine_guid(self) -> None:
        """When both hostname and machine_guid exist, machine_guid is identity."""
        h = Host(
            evidence_hash=VALID_HASH,
            derivation="recmd",
            hostname="rd01",
            machine_guid=GUID_RD01,
        )
        assert h.canonical_key() == ("Host", GUID_RD01)

    def test_canonical_key_falls_back_to_hostname(self) -> None:
        """Without machine_guid, hostname is identity."""
        h = Host(evidence_hash=VALID_HASH, derivation="recmd", hostname="rd01")
        assert h.canonical_key() == ("Host", "rd01")

    def test_canonical_keys_distinguish_hosts_with_different_guids(self) -> None:
        """Two hosts with same hostname but different machine_guids are distinct."""
        h1 = Host(
            evidence_hash=VALID_HASH, derivation="recmd", hostname="rd01", machine_guid=GUID_RD01
        )
        h2 = Host(
            evidence_hash=VALID_HASH, derivation="recmd", hostname="rd01", machine_guid=GUID_DC01
        )
        assert h1.canonical_key() != h2.canonical_key()

    # ---- merge_into ----

    def test_merge_fills_null_fields(self) -> None:
        """If self has no machine_guid and other does, take it."""
        h1 = Host(evidence_hash=VALID_HASH, derivation="src1", hostname="rd01")
        h2 = Host(
            evidence_hash=VALID_HASH,
            derivation="src2",
            hostname="rd01",
            machine_guid=GUID_RD01,
            os_version="Windows Server 2022",
        )
        h1.merge_into(h2)
        assert h1.machine_guid == GUID_RD01
        assert h1.os_version == "Windows Server 2022"

    def test_merge_does_not_overwrite_existing(self) -> None:
        """Existing values are not replaced by merge."""
        h1 = Host(
            evidence_hash=VALID_HASH,
            derivation="src1",
            hostname="rd01",
            os_version="Windows Server 2022",
        )
        h2 = Host(
            evidence_hash=VALID_HASH,
            derivation="src2",
            hostname="rd01",
            os_version="Windows 11",
        )
        h1.merge_into(h2)
        # h1 keeps its original value, doesn't take h2's
        assert h1.os_version == "Windows Server 2022"

    def test_merge_rejects_non_host(self) -> None:
        """Merging a different type into Host raises TypeError."""
        h = Host(evidence_hash=VALID_HASH, derivation="src1", hostname="rd01")
        # We use a string here as a non-Host stand-in. The isinstance check should reject it.
        with pytest.raises(TypeError):
            h.merge_into("not a node")  # type: ignore[arg-type]

# =============================================================================
# User
# =============================================================================


SID_SYSTEM = "S-1-5-18"
SID_NETWORK = "S-1-5-20"
SID_USER_RSYDOW = "S-1-5-21-1234567890-1234567890-1234567890-1001"


class TestUser:
    """Schema section 2.6 — User node."""

    def test_minimal_construction(self) -> None:
        u = User(evidence_hash=VALID_HASH, derivation="getsids", sid=SID_USER_RSYDOW)
        assert u.sid == SID_USER_RSYDOW
        assert u.username is None
        assert u.domain is None
        assert u.account_type is None

    def test_full_construction(self) -> None:
        u = User(
            evidence_hash=VALID_HASH,
            derivation="evtx_4624",
            sid=SID_USER_RSYDOW,
            username="rsydow-a",
            domain="SHIELDBASE",
            account_type="domain",
        )
        assert u.username == "rsydow-a"
        assert u.account_type == "domain"

    def test_sid_required(self) -> None:
        with pytest.raises(ValidationError):
            User(evidence_hash=VALID_HASH, derivation="getsids")  # type: ignore[call-arg]

    def test_sid_min_length(self) -> None:
        with pytest.raises(ValidationError):
            User(evidence_hash=VALID_HASH, derivation="getsids", sid="S-1")

    def test_canonical_key_is_sid(self) -> None:
        u = User(
            evidence_hash=VALID_HASH,
            derivation="getsids",
            sid=SID_USER_RSYDOW,
            username="rsydow-a",
        )
        assert u.canonical_key() == ("User", SID_USER_RSYDOW)

    def test_canonical_key_not_host_scoped(self) -> None:
        """Same SID seen via two different hosts produces the same canonical key."""
        u1 = User(evidence_hash=VALID_HASH, derivation="getsids rd01", sid=SID_SYSTEM)
        u2 = User(evidence_hash=VALID_HASH, derivation="getsids dc01", sid=SID_SYSTEM)
        assert u1.canonical_key() == u2.canonical_key()

    def test_merge_fills_null_username(self) -> None:
        u1 = User(evidence_hash=VALID_HASH, derivation="src1", sid=SID_USER_RSYDOW)
        u2 = User(
            evidence_hash=VALID_HASH,
            derivation="src2",
            sid=SID_USER_RSYDOW,
            username="rsydow-a",
            domain="SHIELDBASE",
        )
        u1.merge_into(u2)
        assert u1.username == "rsydow-a"
        assert u1.domain == "SHIELDBASE"

    def test_merge_does_not_overwrite_existing_username(self) -> None:
        u1 = User(
            evidence_hash=VALID_HASH,
            derivation="src1",
            sid=SID_USER_RSYDOW,
            username="rsydow-a",
        )
        u2 = User(
            evidence_hash=VALID_HASH,
            derivation="src2",
            sid=SID_USER_RSYDOW,
            username="different_name",
        )
        u1.merge_into(u2)
        assert u1.username == "rsydow-a"

    def test_merge_takes_more_specific_account_type(self) -> None:
        """If self has 'well-known' and other has 'domain', take 'domain'."""
        u1 = User(
            evidence_hash=VALID_HASH,
            derivation="src1",
            sid=SID_USER_RSYDOW,
            account_type="well-known",
        )
        u2 = User(
            evidence_hash=VALID_HASH,
            derivation="src2",
            sid=SID_USER_RSYDOW,
            account_type="domain",
        )
        u1.merge_into(u2)
        assert u1.account_type == "domain"

    def test_merge_keeps_more_specific_account_type(self) -> None:
        """If self has 'domain' and other has 'well-known', keep 'domain'."""
        u1 = User(
            evidence_hash=VALID_HASH,
            derivation="src1",
            sid=SID_USER_RSYDOW,
            account_type="domain",
        )
        u2 = User(
            evidence_hash=VALID_HASH,
            derivation="src2",
            sid=SID_USER_RSYDOW,
            account_type="well-known",
        )
        u1.merge_into(u2)
        assert u1.account_type == "domain"

    def test_merge_rejects_non_user(self) -> None:
        u = User(evidence_hash=VALID_HASH, derivation="src", sid=SID_USER_RSYDOW)
        h = Host(evidence_hash=VALID_HASH, derivation="src", hostname="rd01")
        with pytest.raises(TypeError):
            u.merge_into(h)


# =============================================================================
# NetworkEndpoint
# =============================================================================


class TestNetworkEndpoint:
    """Schema section 2.5 — NetworkEndpoint node."""

    def test_minimal_construction(self) -> None:
        n = NetworkEndpoint(
            evidence_hash=VALID_HASH,
            derivation="netscan",
            protocol="TCP",
            remote_addr="172.16.6.12",
            remote_port=445,
        )
        assert n.protocol == "TCP"
        assert n.remote_port == 445
        assert n.domain is None
        assert n.is_internal is False

    def test_port_must_be_in_range(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEndpoint(
                evidence_hash=VALID_HASH,
                derivation="netscan",
                protocol="TCP",
                remote_addr="1.2.3.4",
                remote_port=70000,
            )

    def test_negative_port_rejected(self) -> None:
        with pytest.raises(ValidationError):
            NetworkEndpoint(
                evidence_hash=VALID_HASH,
                derivation="netscan",
                protocol="TCP",
                remote_addr="1.2.3.4",
                remote_port=-1,
            )

    def test_canonical_key_three_tuple(self) -> None:
        n = NetworkEndpoint(
            evidence_hash=VALID_HASH,
            derivation="netscan",
            protocol="SMB",
            remote_addr="172.16.6.12",
            remote_port=445,
        )
        assert n.canonical_key() == ("NetworkEndpoint", "SMB", "172.16.6.12", 445)

    def test_canonical_key_not_host_scoped(self) -> None:
        """Same endpoint seen from rd01 and dc01 should produce the same key."""
        from_rd01 = NetworkEndpoint(
            evidence_hash=VALID_HASH,
            derivation="netscan rd01",
            protocol="TCP",
            remote_addr="172.15.1.20",
            remote_port=443,
        )
        from_dc01 = NetworkEndpoint(
            evidence_hash=VALID_HASH,
            derivation="netscan dc01",
            protocol="TCP",
            remote_addr="172.15.1.20",
            remote_port=443,
        )
        assert from_rd01.canonical_key() == from_dc01.canonical_key()

    def test_different_protocols_distinct(self) -> None:
        """Same IP+port but TCP vs UDP = two different endpoints."""
        tcp = NetworkEndpoint(
            evidence_hash=VALID_HASH,
            derivation="netscan",
            protocol="TCP",
            remote_addr="1.2.3.4",
            remote_port=53,
        )
        udp = NetworkEndpoint(
            evidence_hash=VALID_HASH,
            derivation="netscan",
            protocol="UDP",
            remote_addr="1.2.3.4",
            remote_port=53,
        )
        assert tcp.canonical_key() != udp.canonical_key()

    def test_merge_fills_null_domain(self) -> None:
        n1 = NetworkEndpoint(
            evidence_hash=VALID_HASH,
            derivation="netscan",
            protocol="TCP",
            remote_addr="1.2.3.4",
            remote_port=443,
        )
        n2 = NetworkEndpoint(
            evidence_hash=VALID_HASH,
            derivation="dns",
            protocol="TCP",
            remote_addr="1.2.3.4",
            remote_port=443,
            domain="evil.example.com",
        )
        n1.merge_into(n2)
        assert n1.domain == "evil.example.com"

    def test_merge_preserves_existing_domain(self) -> None:
        n1 = NetworkEndpoint(
            evidence_hash=VALID_HASH,
            derivation="netscan",
            protocol="TCP",
            remote_addr="1.2.3.4",
            remote_port=443,
            domain="first.example.com",
        )
        n2 = NetworkEndpoint(
            evidence_hash=VALID_HASH,
            derivation="dns",
            protocol="TCP",
            remote_addr="1.2.3.4",
            remote_port=443,
            domain="different.example.com",
        )
        n1.merge_into(n2)
        assert n1.domain == "first.example.com"

    def test_merge_rejects_non_endpoint(self) -> None:
        n = NetworkEndpoint(
            evidence_hash=VALID_HASH,
            derivation="netscan",
            protocol="TCP",
            remote_addr="1.2.3.4",
            remote_port=443,
        )
        h = Host(evidence_hash=VALID_HASH, derivation="src", hostname="rd01")
        with pytest.raises(TypeError):
            n.merge_into(h)


# =============================================================================
# File
# =============================================================================


from datetime import datetime, timezone


HASH_STUN = "deadbeef" * 8  # 64 hex chars
HASH_OTHER = "c0ffee" * 10 + "abcd"  # 64 hex chars


class TestFile:
    """Schema section 2.3 — File node."""

    def test_minimal_construction(self) -> None:
        f = File(
            evidence_hash=VALID_HASH,
            derivation="fls rd01.E01",
            host_hostname="rd01",
            full_path="C:\\Windows\\System32\\STUN.exe",
        )
        assert f.host_hostname == "rd01"
        assert f.on_disk is False  # default
        assert f.is_deleted is False
        assert f.referenced_by == []

    # ---- canonical_key ----

    def test_canonical_key_normalizes_path(self) -> None:
        """Backslashes -> forward, lowercased."""
        f = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="rd01",
            full_path="C:\\Windows\\System32\\STUN.exe",
        )
        assert f.canonical_key() == ("File", "rd01", "c:/windows/system32/stun.exe")

    def test_canonical_key_strips_nt_prefix(self) -> None:
        """\\??\\C:\\... -> c:/..."""
        f = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="rd01",
            full_path="\\??\\C:\\Users\\admin\\file.txt",
        )
        assert f.canonical_key() == ("File", "rd01", "c:/users/admin/file.txt")

    def test_canonical_keys_match_across_case_differences(self) -> None:
        """Two ingestions with case differences = same canonical key."""
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="rd01",
            full_path="C:\\WINDOWS\\System32\\STUN.exe",
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="autorunsc",
            host_hostname="rd01",
            full_path="c:\\windows\\system32\\stun.exe",
        )
        assert f1.canonical_key() == f2.canonical_key()

    def test_canonical_keys_distinguish_hosts(self) -> None:
        """Same path on rd01 and dc01 = different nodes."""
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="rd01",
            full_path="C:\\Windows\\System32\\STUN.exe",
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="dc01",
            full_path="C:\\Windows\\System32\\STUN.exe",
        )
        assert f1.canonical_key() != f2.canonical_key()

    # ---- the negative-evidence pattern ----

    def test_atmfd_dll_pattern(self) -> None:
        """The canonical 'referenced in Autoruns but absent from disk' pattern.

        Schema-promised use case: a finding can claim 'deleted/missing malware'
        when referenced_by is non-empty AND on_disk is False.
        """
        f = File(
            evidence_hash=VALID_HASH,
            derivation="autorunsc",
            host_hostname="rd01",
            full_path="C:\\Windows\\System32\\atmfd.dll",
            on_disk=False,
            referenced_by=["autoruns"],
        )
        assert f.on_disk is False
        assert "autoruns" in f.referenced_by

    # ---- merge_into ----

    def test_merge_unions_referenced_by(self) -> None:
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="autorunsc",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            referenced_by=["autoruns"],
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="shimcache",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            referenced_by=["shimcache", "amcache"],
        )
        f1.merge_into(f2)
        assert f1.referenced_by == ["autoruns", "shimcache", "amcache"]

    def test_merge_referenced_by_deduplicates(self) -> None:
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            referenced_by=["autoruns", "shimcache"],
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            referenced_by=["shimcache", "amcache"],
        )
        f1.merge_into(f2)
        assert f1.referenced_by == ["autoruns", "shimcache", "amcache"]
        # shimcache appears once, not twice

    def test_merge_on_disk_uses_or(self) -> None:
        """If any source confirms disk presence, on_disk becomes True."""
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="autorunsc",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            on_disk=False,
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            on_disk=True,
        )
        f1.merge_into(f2)
        assert f1.on_disk is True

    def test_merge_hash_conflict_raises(self) -> None:
        """Different sha256 on same path means different file — should not merge."""
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            sha256=HASH_STUN,
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            sha256=HASH_OTHER,
        )
        with pytest.raises(ValueError, match="Hash conflict"):
            f1.merge_into(f2)

    def test_merge_fills_null_hash(self) -> None:
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            sha256=HASH_STUN,
        )
        f1.merge_into(f2)
        assert f1.sha256 == HASH_STUN

    def test_merge_mtime_keeps_earliest(self) -> None:
        """mtime/ctime/btime keep the earliest known."""
        early = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        later = datetime(2023, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            mtime=later,
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            mtime=early,
        )
        f1.merge_into(f2)
        assert f1.mtime == early

    def test_merge_atime_keeps_latest(self) -> None:
        """atime keeps the latest known."""
        early = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        later = datetime(2023, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            atime=early,
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            atime=later,
        )
        f1.merge_into(f2)
        assert f1.atime == later

    def test_merge_rejects_non_file(self) -> None:
        f = File(
            evidence_hash=VALID_HASH,
            derivation="src",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
        )
        h = Host(evidence_hash=VALID_HASH, derivation="src", hostname="rd01")
        with pytest.raises(TypeError):
            f.merge_into(h)


# =============================================================================
# File
# =============================================================================


from datetime import datetime, timezone


HASH_STUN = "deadbeef" * 8  # 64 hex chars
HASH_OTHER = "c0ffee" * 10 + "abcd"  # 64 hex chars


class TestFile:
    """Schema section 2.3 — File node."""

    def test_minimal_construction(self) -> None:
        f = File(
            evidence_hash=VALID_HASH,
            derivation="fls rd01.E01",
            host_hostname="rd01",
            full_path="C:\\Windows\\System32\\STUN.exe",
        )
        assert f.host_hostname == "rd01"
        assert f.on_disk is False  # default
        assert f.is_deleted is False
        assert f.referenced_by == []

    # ---- canonical_key ----

    def test_canonical_key_normalizes_path(self) -> None:
        """Backslashes -> forward, lowercased."""
        f = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="rd01",
            full_path="C:\\Windows\\System32\\STUN.exe",
        )
        assert f.canonical_key() == ("File", "rd01", "c:/windows/system32/stun.exe")

    def test_canonical_key_strips_nt_prefix(self) -> None:
        """\\??\\C:\\... -> c:/..."""
        f = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="rd01",
            full_path="\\??\\C:\\Users\\admin\\file.txt",
        )
        assert f.canonical_key() == ("File", "rd01", "c:/users/admin/file.txt")

    def test_canonical_keys_match_across_case_differences(self) -> None:
        """Two ingestions with case differences = same canonical key."""
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="rd01",
            full_path="C:\\WINDOWS\\System32\\STUN.exe",
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="autorunsc",
            host_hostname="rd01",
            full_path="c:\\windows\\system32\\stun.exe",
        )
        assert f1.canonical_key() == f2.canonical_key()

    def test_canonical_keys_distinguish_hosts(self) -> None:
        """Same path on rd01 and dc01 = different nodes."""
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="rd01",
            full_path="C:\\Windows\\System32\\STUN.exe",
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="dc01",
            full_path="C:\\Windows\\System32\\STUN.exe",
        )
        assert f1.canonical_key() != f2.canonical_key()

    # ---- the negative-evidence pattern ----

    def test_atmfd_dll_pattern(self) -> None:
        """The canonical 'referenced in Autoruns but absent from disk' pattern.

        Schema-promised use case: a finding can claim 'deleted/missing malware'
        when referenced_by is non-empty AND on_disk is False.
        """
        f = File(
            evidence_hash=VALID_HASH,
            derivation="autorunsc",
            host_hostname="rd01",
            full_path="C:\\Windows\\System32\\atmfd.dll",
            on_disk=False,
            referenced_by=["autoruns"],
        )
        assert f.on_disk is False
        assert "autoruns" in f.referenced_by

    # ---- merge_into ----

    def test_merge_unions_referenced_by(self) -> None:
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="autorunsc",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            referenced_by=["autoruns"],
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="shimcache",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            referenced_by=["shimcache", "amcache"],
        )
        f1.merge_into(f2)
        assert f1.referenced_by == ["autoruns", "shimcache", "amcache"]

    def test_merge_referenced_by_deduplicates(self) -> None:
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            referenced_by=["autoruns", "shimcache"],
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            referenced_by=["shimcache", "amcache"],
        )
        f1.merge_into(f2)
        assert f1.referenced_by == ["autoruns", "shimcache", "amcache"]
        # shimcache appears once, not twice

    def test_merge_on_disk_uses_or(self) -> None:
        """If any source confirms disk presence, on_disk becomes True."""
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="autorunsc",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            on_disk=False,
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="fls",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            on_disk=True,
        )
        f1.merge_into(f2)
        assert f1.on_disk is True

    def test_merge_hash_conflict_raises(self) -> None:
        """Different sha256 on same path means different file — should not merge."""
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            sha256=HASH_STUN,
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            sha256=HASH_OTHER,
        )
        with pytest.raises(ValueError, match="Hash conflict"):
            f1.merge_into(f2)

    def test_merge_fills_null_hash(self) -> None:
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            sha256=HASH_STUN,
        )
        f1.merge_into(f2)
        assert f1.sha256 == HASH_STUN

    def test_merge_mtime_keeps_earliest(self) -> None:
        """mtime/ctime/btime keep the earliest known."""
        early = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        later = datetime(2023, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            mtime=later,
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            mtime=early,
        )
        f1.merge_into(f2)
        assert f1.mtime == early

    def test_merge_atime_keeps_latest(self) -> None:
        """atime keeps the latest known."""
        early = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        later = datetime(2023, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        f1 = File(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            atime=early,
        )
        f2 = File(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
            atime=later,
        )
        f1.merge_into(f2)
        assert f1.atime == later

    def test_merge_rejects_non_file(self) -> None:
        f = File(
            evidence_hash=VALID_HASH,
            derivation="src",
            host_hostname="rd01",
            full_path="C:\\foo.exe",
        )
        h = Host(evidence_hash=VALID_HASH, derivation="src", hostname="rd01")
        with pytest.raises(TypeError):
            f.merge_into(h)


# =============================================================================
# RegistryKey
# =============================================================================


class TestRegistryKey:
    """Schema section 2.4 — RegistryKey node."""

    def test_minimal_construction(self) -> None:
        rk = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="recmd SYSTEM",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="CurrentControlSet\\Services\\pssdnsvc",
        )
        assert rk.value_name is None
        assert rk.value_data is None

    def test_canonical_key_with_value_name(self) -> None:
        rk = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="recmd",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="CurrentControlSet\\Services\\pssdnsvc",
            value_name="ImagePath",
        )
        assert rk.canonical_key() == (
            "RegistryKey",
            "rd01",
            "SYSTEM",
            "currentcontrolset/services/pssdnsvc",
            "ImagePath",
        )

    def test_canonical_key_for_key_itself(self) -> None:
        rk = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="recmd",
            host_hostname="rd01",
            hive_name="SOFTWARE",
            key_path="Microsoft\\Windows\\CurrentVersion\\Run",
        )
        # value_name is None — represents the key itself
        assert rk.canonical_key()[-1] is None

    def test_canonical_key_normalizes_path(self) -> None:
        """Backslashes -> forward, lowercased, leading/trailing slashes stripped."""
        rk1 = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="\\CurrentControlSet\\Services\\foo\\",
        )
        rk2 = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="CurrentControlSet/Services/FOO",
        )
        assert rk1.canonical_key() == rk2.canonical_key()

    def test_canonical_keys_distinguish_hives(self) -> None:
        """Same key path in SYSTEM vs SOFTWARE = different nodes."""
        rk1 = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="src",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="foo\\bar",
        )
        rk2 = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="src",
            host_hostname="rd01",
            hive_name="SOFTWARE",
            key_path="foo\\bar",
        )
        assert rk1.canonical_key() != rk2.canonical_key()

    def test_merge_takes_latest_write_time(self) -> None:
        early = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        late = datetime(2023, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        rk1 = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="foo",
            value_data="old",
            last_write_time=early,
        )
        rk2 = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="foo",
            value_data="new",
            last_write_time=late,
        )
        rk1.merge_into(rk2)
        assert rk1.value_data == "new"
        assert rk1.last_write_time == late

    def test_merge_keeps_self_when_newer(self) -> None:
        early = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        late = datetime(2023, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        rk1 = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="foo",
            value_data="newer",
            last_write_time=late,
        )
        rk2 = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="foo",
            value_data="older",
            last_write_time=early,
        )
        rk1.merge_into(rk2)
        assert rk1.value_data == "newer"  # self is newer, kept

    def test_merge_fills_nulls(self) -> None:
        rk1 = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="src1",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="foo",
        )
        rk2 = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="src2",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="foo",
            value_data="something",
            value_type="REG_SZ",
        )
        rk1.merge_into(rk2)
        assert rk1.value_data == "something"
        assert rk1.value_type == "REG_SZ"

    def test_merge_rejects_non_registrykey(self) -> None:
        rk = RegistryKey(
            evidence_hash=VALID_HASH,
            derivation="src",
            host_hostname="rd01",
            hive_name="SYSTEM",
            key_path="foo",
        )
        h = Host(evidence_hash=VALID_HASH, derivation="src", hostname="rd01")
        with pytest.raises(TypeError):
            rk.merge_into(h)
