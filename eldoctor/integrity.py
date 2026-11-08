"""Integrity primitives owned by the agent: keys, record seals and the hash-chained audit trail.

Why this exists
    Approvals (the safety valve of interactive mode), user roles and the audit trail used to be
    plain rows in an editable SQLite file, and the agent trusted them as-is.  Anyone able to write
    the file could forge an approval "by admin1" and have the agent kill a process, then rewrite the
    audit trail to hide it.

What this module provides
    * ``Keyring``: a 256-bit master key in ``<data>/keys/master.key`` (0600, folder 0700, owned by
      the service account) from which purpose-specific keys are derived (HMAC-based KDF).  Only the
      agent process can read it: clients never see it.
    * ``seal`` / ``check_seal``: HMAC-SHA256 over a canonical encoding of the security-relevant
      fields of a row (approval request, approval decision, user role/status, quarantine record,
      IP block).  A row edited outside the agent no longer matches its seal, and a row *inserted*
      outside the agent has no valid seal at all.  Forging a seal requires the key.
    * ``audit_hash`` / ``audit_mac``: every audit record carries ``prev_hash`` and
      ``hash = SHA-256(canonical record + prev_hash)``, so modifying, inserting or deleting any record
      breaks the chain from that point on.  The hash is *unkeyed* on purpose: a SIEM or an auditor can
      verify the chain without any secret.  ``mac = HMAC(audit key, hash)`` additionally proves the
      agent wrote the record, so an attacker cannot simply recompute the whole chain after an edit.
      A sealed head pointer (last seq + hash) detects truncation of the tail.

    * ``SigningChain``: **forward-secure, publicly verifiable signatures** (format v2).  Every audit
      record is signed with a *one-time* Ed25519 key; the record commits to the public key of the key
      that will sign the next record, and the used private key is destroyed right after the commit.
      Consequences:
        - whoever steals every file at time T (root included) holds only the key for the *next*
          record: no record written before T can be altered or re-signed;
        - rebuilding the whole chain from a new first key changes the *genesis fingerprint*, which is
          shown by ``eldoctor audit verify``, forwarded to the SIEM with the first record and can be
          pinned in ``audit.genesis_fingerprint``;
        - signatures are verified with public keys only, so the SIEM / an auditor verifies the chain
          without any secret (``eldoctor audit verify-export``).
    * the *ledger*: records may reference a row of another table (``ref_kind``, ``ref_id``,
      ``ref_digest``).  Every write to alerts, actions, users, IP blocks and quarantine records appends
      the row's digest to the signed chain, and the agent checks rows against it before acting.  The
      HMAC seals above remain as a fast first check; the signed chain is the authority.

What remains (documented)
    An attacker who controls the machine *while the agent runs* can append new records with the
    current one-time key - exactly as they could run the agent itself.  They cannot change history,
    and everything appended is forwarded to the SIEM in real time.  Used keys are unlinked and
    overwritten; on copy-on-write / SSD storage remnants may survive until the blocks are reused.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from eldoctor.config import IS_WINDOWS

GENESIS = "0" * 64
KEY_BYTES = 32
AUDIT_FIELDS = ("seq", "ts", "actor", "event", "details", "os_user", "os_uid", "os_pid", "client", "host")
AUDIT_V2_FIELDS = AUDIT_FIELDS + ("v", "pub", "next_pub", "ref_kind", "ref_id", "ref_digest")
SIG_CONTEXT = b"eldoctor-audit-v2:"


class IntegrityError(RuntimeError):
    pass


def canon(obj: Any) -> bytes:
    """Deterministic JSON encoding used for every hash / MAC (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def _write_exclusive(path: Path, data: bytes) -> bool:
    """Atomically create `path` with mode 0600. Returns False if it already exists (another process won)."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        try:
            os.link(str(tmp), str(path))          # atomic and exclusive: fails if the key already exists
        except (AttributeError, NotImplementedError):   # pragma: no cover - filesystems without hard links
            if path.exists():
                return False
            os.rename(str(tmp), str(path))
            return True
        except FileExistsError:
            return False
        return True
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


class Keyring:
    """Master key of one El Doctor data folder and the keys derived from it."""

    def __init__(self, data_dir: Path) -> None:
        self.dir = Path(data_dir) / "keys"
        self.dir.mkdir(parents=True, exist_ok=True)
        if not IS_WINDOWS:
            try:
                os.chmod(self.dir, 0o700)
            except OSError:
                pass
        self.path = self.dir / "master.key"
        self.created = False
        if not self.path.exists():
            self.created = _write_exclusive(self.path, secrets.token_bytes(KEY_BYTES).hex().encode())
        raw = self.path.read_bytes().strip()
        try:
            self.master = bytes.fromhex(raw.decode())
        except ValueError as exc:
            raise IntegrityError(f"corrupt key file {self.path}") from exc
        if len(self.master) < KEY_BYTES:
            raise IntegrityError(f"key file {self.path} is too short")
        self._cache: Dict[str, bytes] = {}

    @property
    def kid(self) -> str:
        """Public key identifier (never the key itself)."""
        return hashlib.sha256(b"eldoctor-kid" + self.master).hexdigest()[:12]

    def key(self, purpose: str) -> bytes:
        k = self._cache.get(purpose)
        if k is None:
            k = hmac.new(self.master, b"eldoctor/v1/" + purpose.encode(), hashlib.sha256).digest()
            self._cache[purpose] = k
        return k

    # ------------------------------------------------------------------ seals
    def seal(self, kind: str, fields: Iterable[Any]) -> str:
        return hmac.new(self.key(f"seal:{kind}"), canon([kind, list(fields)]), hashlib.sha256).hexdigest()

    def check_seal(self, kind: str, fields: Iterable[Any], mac: Optional[str]) -> bool:
        if not mac:
            return False
        return hmac.compare_digest(self.seal(kind, fields), str(mac))

    # ------------------------------------------------------------------ audit chain
    def audit_mac(self, record_hash: str) -> str:
        return hmac.new(self.key("audit"), record_hash.encode(), hashlib.sha256).hexdigest()


def audit_hash(rec: Dict[str, Any], prev_hash: str) -> str:
    """Unkeyed chain hash of one audit record: anyone (SIEM, auditor) can recompute it.

    v1 records (first release of the chain) hash the base fields; v2 records also commit to their
    signing key, the next signing key and the ledger reference."""
    v2 = int(rec.get("v") or 1) >= 2
    body = {k: rec.get(k) for k in (AUDIT_V2_FIELDS if v2 else AUDIT_FIELDS)}
    body["ts"] = float(body["ts"] or 0.0)
    body["seq"] = int(body["seq"])
    body["os_pid"] = int(body["os_pid"] or 0)
    if v2:
        body["v"] = 2
        for k in ("pub", "next_pub", "ref_kind", "ref_id", "ref_digest"):
            body[k] = body[k] or ""
    body["prev_hash"] = prev_hash
    return hashlib.sha256(canon(body)).hexdigest()


def row_digest(kind: str, fields: Iterable[Any]) -> str:
    """Public digest of a table row, recorded in the signed chain (the ledger)."""
    return hashlib.sha256(canon(["eldoctor-row-v1", kind, list(fields)])).hexdigest()


def fingerprint(pub_hex: str) -> str:
    """Human-checkable fingerprint of a signing key (e.g. the chain's genesis key)."""
    if not pub_hex:
        return ""
    d = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]
    return "ed25519:" + ":".join(d[i:i + 4] for i in range(0, 32, 4))


# --------------------------------------------------------------------------- forward-secure signatures
def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as exc:          # pragma: no cover - dependency declared in requirements.txt
        raise IntegrityError("the 'cryptography' package is required for signed audit records "
                             "(python -m pip install -r requirements.txt)") from exc
    return Ed25519PrivateKey, Ed25519PublicKey


def verify_signature(pub_hex: str, record_hash: str, sig_hex: str) -> bool:
    """Ed25519 signature of a v2 record - needs only the public key (SIEM / auditor side)."""
    _, pub_cls = _ed25519()
    try:
        pub_cls.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex),
                                                                  SIG_CONTEXT + record_hash.encode())
        return True
    except Exception:
        return False


class SigningChain:
    """One-time signing keys for the audit chain, stored as ``keys/audit-chain/<public key>.key``.

    Only the key that will sign the *next* record exists on disk; a key is destroyed as soon as the
    record it signed is committed."""

    def __init__(self, keys_dir: Path) -> None:
        self.dir = Path(keys_dir) / "audit-chain"
        self.dir.mkdir(parents=True, exist_ok=True)
        if not IS_WINDOWS:
            try:
                os.chmod(self.dir, 0o700)
            except OSError:
                pass

    def _path(self, pub_hex: str) -> Path:
        if not pub_hex or any(c not in "0123456789abcdef" for c in pub_hex):
            raise IntegrityError("invalid public key")
        return self.dir / f"{pub_hex}.key"

    def new_key(self):
        """Generate a key, persist it durably (0600, fsync) and return (private key, public hex)."""
        priv_cls, _ = _ed25519()
        from cryptography.hazmat.primitives import serialization
        sk = priv_cls.generate()
        raw = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
        pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        fd = os.open(str(self._path(pub)), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, raw.hex().encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        return sk, pub

    def load(self, pub_hex: str):
        """The private key for `pub_hex`, or None if it does not exist (lost or already used)."""
        priv_cls, _ = _ed25519()
        from cryptography.hazmat.primitives import serialization
        try:
            raw = bytes.fromhex(self._path(pub_hex).read_text().strip())
            sk = priv_cls.from_private_bytes(raw)
        except (OSError, ValueError, IntegrityError):
            return None
        if sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex() != pub_hex:
            return None
        return sk

    def destroy(self, pub_hex: str) -> None:
        """Overwrite, then unlink a used key (forward security)."""
        try:
            p = self._path(pub_hex)
            size = p.stat().st_size
            with open(p, "r+b", buffering=0) as fh:
                fh.write(b"\0" * size)
                os.fsync(fh.fileno())
            p.unlink()
        except (OSError, IntegrityError):
            pass

    def cleanup(self, keep: str) -> None:
        """Destroy every key except the one that will sign the next record (left-overs of a crash)."""
        for f in self.dir.glob("*.key"):
            if f.stem != keep:
                self.destroy(f.stem)

    @staticmethod
    def sign(sk, record_hash: str) -> str:
        return sk.sign(SIG_CONTEXT + record_hash.encode()).hex()


def verify_records(rows: List[Dict[str, Any]], keyring: Optional[Keyring], prev_hash: str = GENESIS,
                   first_seq: int = 1, check_mac: bool = True, prev_next_pub: Optional[str] = None,
                   genesis_seen: bool = False) -> Dict[str, Any]:
    """Verify a contiguous slice of audit records.

    Returns {ok, checked, last_seq, last_hash, last_next_pub, genesis, problems}.  Detects: modified
    records (hash mismatch), records not written by this agent (MAC mismatch, v1/v2), forged or
    re-signed records (Ed25519 signature, v2), a signing-key chain that does not continue (rewrite or
    lost key), and deleted / inserted records (seq gap, prev_hash mismatch)."""
    problems: List[Dict[str, Any]] = []
    expect_seq, expect_prev = first_seq, prev_hash
    next_pub, genesis = prev_next_pub, None
    for r in rows:
        seq = int(r["seq"])
        if seq != expect_seq:
            problems.append({"seq": seq, "problem": f"sequence gap: expected {expect_seq} (records deleted "
                                                    f"or inserted)"})
        if r.get("prev_hash") != expect_prev:
            problems.append({"seq": seq, "problem": "prev_hash does not match the previous record"})
        calc = audit_hash(r, r.get("prev_hash") or "")
        if calc != r.get("hash"):
            problems.append({"seq": seq, "problem": "record content was modified (hash mismatch)"})
        elif check_mac and keyring is not None \
                and not hmac.compare_digest(keyring.audit_mac(calc), str(r.get("mac") or "")):
            problems.append({"seq": seq, "problem": "record not written by this agent (MAC mismatch)"})
        if int(r.get("v") or 1) >= 2:
            pub = r.get("pub") or ""
            if not pub or not verify_signature(pub, calc, str(r.get("sig") or "")):
                problems.append({"seq": seq, "problem": "signature invalid (record forged or re-signed)"})
            if next_pub:
                if pub != next_pub:
                    problems.append({"seq": seq, "problem": "signing key does not continue the chain (records "
                                                            "rewritten, or a signing key was lost)"})
            elif genesis_seen or genesis:
                problems.append({"seq": seq, "problem": "a second key chain starts here (chain rewritten)"})
            else:
                genesis = pub
            next_pub = r.get("next_pub") or ""
        elif next_pub:
            problems.append({"seq": seq, "problem": "unsigned record after signed records (downgrade)"})
        expect_seq, expect_prev = seq + 1, r.get("hash") or ""
    return {"ok": not problems, "checked": len(rows), "last_seq": expect_seq - 1, "last_hash": expect_prev,
            "last_next_pub": next_pub, "genesis": genesis, "problems": problems}
