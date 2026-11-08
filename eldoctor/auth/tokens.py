"""Stateless session tokens: compact JWTs (RFC 7519), HS256, signed by the agent.

* The signing key is derived from the agent's master key (``eldoctor.integrity.Keyring``) and never
  leaves the agent process; clients only ever hold the opaque token.
* No server-side session table: the signature, audience, issuer and expiry are verified on every
  request.  Claims: ``sub`` (username), ``uid`` (user id), ``role`` (informational), ``tv`` (the
  user's token version), ``ouid`` / ``osu`` (OS account of the peer that logged in), ``jti``,
  ``iat``, ``nbf``, ``exp``.
* Binding to the OS account: a token is only accepted on a connection whose kernel-verified peer
  credentials belong to the same OS account that logged in, so a copied token file is useless to
  another local user.
* Revocation without sessions: logout denylists the ``jti`` until it expires; a role change, a
  disabled account or "log out everywhere" bumps the user's ``token_version`` and every older token
  stops working.  Authorisation always uses the *current* role from the sealed user record, never the
  ``role`` claim, so a demotion takes effect immediately.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, Optional

ALG = "HS256"
AUDIENCE = "eldoctor-api"
LEEWAY = 30.0


class TokenError(Exception):
    pass


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    if not isinstance(s, str) or len(s) > 8192:
        raise TokenError("malformed token")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (ValueError, TypeError) as exc:
        raise TokenError("malformed token") from exc


class TokenService:
    def __init__(self, key: bytes, issuer: str, kid: str = "", lifetime_s: float = 12 * 3600) -> None:
        if len(key) < 32:
            raise ValueError("token signing key must be at least 256 bits")
        self._key = key
        self.issuer = issuer
        self.kid = kid
        self.lifetime = float(lifetime_s)

    def _sign(self, signing_input: bytes) -> bytes:
        return hmac.new(self._key, signing_input, hashlib.sha256).digest()

    def issue(self, user, os_uid: str, os_user: str = "", lifetime_s: Optional[float] = None) -> Dict[str, Any]:
        now = time.time()
        claims = {"iss": self.issuer, "aud": AUDIENCE, "sub": user.username, "uid": int(user.id), "role": user.role,
                  "tv": int(getattr(user, "token_version", 0)), "ouid": str(os_uid), "osu": os_user,
                  "jti": secrets.token_hex(16), "iat": int(now), "nbf": int(now),
                  "exp": int(now + (lifetime_s if lifetime_s is not None else self.lifetime))}
        header = {"alg": ALG, "typ": "JWT", "kid": self.kid}
        signing_input = (_b64e(json.dumps(header, separators=(",", ":")).encode()) + "." +
                         _b64e(json.dumps(claims, separators=(",", ":")).encode())).encode("ascii")
        token = signing_input.decode("ascii") + "." + _b64e(self._sign(signing_input))
        return {"token": token, "claims": claims}

    def verify(self, token: str, now: Optional[float] = None) -> Dict[str, Any]:
        """Signature, algorithm, audience, issuer and time checks. Raises TokenError."""
        if not isinstance(token, str) or token.count(".") != 2:
            raise TokenError("malformed token")
        h64, c64, s64 = token.split(".")
        try:
            header = json.loads(_b64d(h64))
            claims = json.loads(_b64d(c64))
        except ValueError as exc:
            raise TokenError("malformed token") from exc
        if not isinstance(header, dict) or header.get("alg") != ALG:      # rejects alg=none / RS256 confusion
            raise TokenError("unsupported token algorithm")
        if not hmac.compare_digest(self._sign(f"{h64}.{c64}".encode("ascii")), _b64d(s64)):
            raise TokenError("invalid token signature")
        if not isinstance(claims, dict):
            raise TokenError("malformed token")
        t = time.time() if now is None else now
        if claims.get("aud") != AUDIENCE or claims.get("iss") != self.issuer:
            raise TokenError("token was issued for another El Doctor agent")
        try:
            exp, nbf = float(claims["exp"]), float(claims.get("nbf", 0))
        except (KeyError, TypeError, ValueError) as exc:
            raise TokenError("malformed token") from exc
        if t > exp + LEEWAY:
            raise TokenError("session expired")
        if t + LEEWAY < nbf:
            raise TokenError("token not valid yet")
        for k in ("sub", "uid", "jti", "ouid"):
            if k not in claims:
                raise TokenError("malformed token")
        return claims
