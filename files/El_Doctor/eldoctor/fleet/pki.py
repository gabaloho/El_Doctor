"""The hub's private certificate authority, and the enrollment token.

* The hub CA signs the hub's TLS server certificate (EKU serverAuth) and one client certificate per agent
  (EKU clientAuth, CN = agent id).  Agents generate their own key and send a CSR: private keys never travel.
  Because of the EKUs, an agent certificate can never pass as the hub (OpenSSL checks the purpose).
* The enrollment token carries everything an agent needs to bootstrap trust: the hub URL, a one-time secret and
  the SHA-256 fingerprint of the CA.  The agent downloads the CA certificate, checks it against the fingerprint
  in the token, and pins it: no trust-on-first-use, nothing else to copy.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import json
import secrets
from typing import Dict, List, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

TOKEN_PREFIX = "EDH1-"


class PkiError(ValueError):
    pass


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def load_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def load_cert(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)


def fingerprint_der(der: bytes) -> str:
    return "sha256:" + hashlib.sha256(der).hexdigest()


def fingerprint(cert: x509.Certificate) -> str:
    return fingerprint_der(cert.public_bytes(serialization.Encoding.DER))


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "El Doctor"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def create_ca(common_name: str = "El Doctor Hub CA", years: int = 10) -> Tuple[object, x509.Certificate]:
    key = new_key()
    now = _now()
    cert = (x509.CertificateBuilder().subject_name(_name(common_name)).issuer_name(_name(common_name))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=365 * years))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def _leaf(ca_key, ca_cert: x509.Certificate, subject: x509.Name, public_key, eku, days: int,
          san: List[x509.GeneralName]) -> x509.Certificate:
    now = _now()
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(public_key)
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
         .not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=True, key_cert_sign=False,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return b.sign(ca_key, hashes.SHA256())


def issue_server_cert(ca_key, ca_cert, names: List[str], days: int = 825) -> Tuple[object, x509.Certificate]:
    """TLS certificate of the hub for every name / IP agents and browsers use to reach it."""
    if not names:
        raise PkiError("the hub needs at least one name or IP address (hub init --name ...)")
    san: List[x509.GeneralName] = []
    for n in names:
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            san.append(x509.DNSName(n))
    key = new_key()
    return key, _leaf(ca_key, ca_cert, _name(names[0]), key.public_key(), ExtendedKeyUsageOID.SERVER_AUTH, days, san)


def make_csr(key, hint: str = "agent") -> bytes:
    csr = x509.CertificateSigningRequestBuilder().subject_name(_name(hint[:64] or "agent")).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


def sign_agent_csr(ca_key, ca_cert, csr_pem: bytes, agent_id: str, days: int = 825) -> x509.Certificate:
    """Client certificate for one agent: the hub chooses the identity (CN = agent id), never the CSR."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except ValueError as exc:
        raise PkiError(f"invalid certificate request: {exc}") from exc
    if not csr.is_signature_valid:
        raise PkiError("certificate request signature is invalid")
    if not isinstance(csr.public_key(), ec.EllipticCurvePublicKey):
        raise PkiError("agent keys must be EC P-256")
    return _leaf(ca_key, ca_cert, _name(agent_id), csr.public_key(), ExtendedKeyUsageOID.CLIENT_AUTH, days,
                 [x509.UniformResourceIdentifier(f"urn:eldoctor:agent:{agent_id}")])


def agent_id_of(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


# --------------------------------------------------------------------------- enrollment token
def make_token(url: str, secret: str, ca_fp: str) -> str:
    body = json.dumps({"u": url, "s": secret, "f": ca_fp}, separators=(",", ":")).encode()
    return TOKEN_PREFIX + base64.urlsafe_b64encode(body).decode().rstrip("=")


def parse_token(token: str) -> Dict[str, str]:
    t = (token or "").strip()
    if not t.startswith(TOKEN_PREFIX):
        raise PkiError("not an El Doctor Hub enrollment token (it starts with EDH1-)")
    raw = t[len(TOKEN_PREFIX):]
    try:
        d = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        url, secret, fp = str(d["u"]), str(d["s"]), str(d["f"])
    except (ValueError, KeyError, TypeError) as exc:
        raise PkiError("the enrollment token is damaged (copy it again, completely)") from exc
    if not url.startswith("https://") or not fp.startswith("sha256:") or len(secret) < 32:
        raise PkiError("the enrollment token is incomplete")
    return {"url": url.rstrip("/"), "secret": secret, "ca_fingerprint": fp}


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def secret_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()
