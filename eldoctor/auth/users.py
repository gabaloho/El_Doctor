"""User registration, authentication and role-based authorisation.

* Registration is mandatory before El Doctor can be used.  The profile
  captures who the user is, the use case and the chosen deployment target.
* The first registered user becomes ``admin``; later self-registrations get
  ``viewer`` until an admin promotes them.  Admins can create users directly.
* Passwords: PBKDF2-HMAC-SHA256 (600k iterations, random salt), constant-time
  comparison, lockout after N failures.
* Sessions: stateless JWTs signed by the agent (``eldoctor.auth.tokens``), bound to the
  caller's OS account; clients keep them in their own per-user folder.  Services and
  automation use an API key (``ELDOCTOR_API_KEY``), stored hashed.
* Integrity: the security-relevant columns of every user row (role, active flag,
  credentials, token version) are sealed with the agent's key.  A role edited directly
  in the database fails the seal and the account is refused - it is never trusted.

Only the agent process uses this module; the CLI, TUI and GUI reach it through the
local API (``eldoctor.api``), which is where every permission check happens.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from eldoctor.config import safe_url
from eldoctor.storage import Store

ROLES = ["viewer", "analyst", "admin"]
PERMISSIONS = {
    "viewer": {"view"},
    "analyst": {"view", "run", "approve", "respond", "intel", "notify_test"},
    "admin": {"view", "run", "approve", "respond", "intel", "notify_test", "enforce", "manage_users",
              "deploy", "restore", "unblock", "config", "audit"},
}
USE_CASES = {
    "personal": "Personal desktop / laptop protection",
    "smb": "Small business servers & workstations",
    "soc": "SOC / MSSP endpoint telemetry & response",
    "cloud": "Cloud workloads (VMs, containers, Kubernetes)",
    "devops": "DevOps / CI runners / build servers",
    "research": "Security research, labs, training (CTF, purple team)",
    "education": "Education / teaching",
    "other": "Other",
}
DEPLOY_TARGETS = {
    "windows": "Windows desktop / server (Scheduled Task or service)",
    "linux": "Linux host (systemd service)",
    "docker": "Docker container on a host",
    "kubernetes": "Kubernetes DaemonSet (every node)",
    "aws": "AWS EC2 (cloud-init user-data)",
    "azure": "Azure VM (custom-data / cloud-init)",
    "gcp": "Google Cloud VM (startup-script)",
}
PBKDF2_ITER = int(os.environ.get("ELDOCTOR_PBKDF2_ITER", "600000"))
USERNAME_RX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{2,31}$")
EMAIL_RX = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")


class AuthError(Exception):
    pass


@dataclass
class User:
    id: int
    username: str
    email: str
    full_name: str
    organization: str
    role: str
    use_case: str
    deployment_target: str
    active: bool = True
    token_version: int = 0

    def can(self, perm: str) -> bool:
        return self.active and perm in PERMISSIONS.get(self.role, set())

    @classmethod
    def from_row(cls, r: Dict[str, Any]) -> "User":
        return cls(r["id"], r["username"], r["email"] or "", r["full_name"] or "", r["organization"] or "",
                   r["role"], r["use_case"] or "", r["deployment_target"] or "", bool(r["active"]),
                   int(r.get("token_version") or 0))

    def public(self) -> Dict[str, Any]:
        return {"id": self.id, "username": self.username, "email": self.email, "full_name": self.full_name,
                "organization": self.organization, "role": self.role, "use_case": self.use_case,
                "deployment_target": self.deployment_target, "active": self.active,
                "permissions": sorted(PERMISSIONS.get(self.role, set())) if self.active else []}


def hash_password(password: str, iterations: int = PBKDF2_ITER) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, it, salt, dk = encoded.split("$")
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(it))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def password_problems(password: str, username: str = "") -> List[str]:
    probs = []
    if len(password) < 10:
        probs.append("at least 10 characters")
    classes = sum(bool(re.search(rx, password)) for rx in (r"[a-z]", r"[A-Z]", r"\d", r"[^a-zA-Z0-9]"))
    if classes < 3:
        probs.append("at least 3 of: lowercase, uppercase, digit, symbol")
    if username and username.lower() in password.lower():
        probs.append("must not contain the username")
    return probs


class UserManager:
    def __init__(self, store: Store, cfg: Optional[Dict[str, Any]] = None) -> None:
        self.store = store
        rc = (cfg or {}).get("registration", {})
        self.session_hours = float(rc.get("session_hours", 12))
        self.lock_attempts = int(rc.get("lockout_attempts", 5))
        self.lock_minutes = float(rc.get("lockout_minutes", 5))
        self.webhook_url = rc.get("webhook_url", "")

    # ------------------------------------------------------------------ registration
    def count(self) -> int:
        return self.store.query("SELECT COUNT(*) AS n FROM users")[0]["n"]

    def register(self, username: str, password: str, email: str, full_name: str = "", organization: str = "",
                 use_case: str = "other", deployment_target: str = "linux", role: Optional[str] = None,
                 created_by: Optional[User] = None, consent_share: bool = False) -> Tuple[User, str]:
        """Create a user; returns (user, api_key).  The API key is shown once."""
        if not USERNAME_RX.match(username or ""):
            raise AuthError("username: 3-32 chars, letters/digits/._-, must start with a letter")
        if not EMAIL_RX.match(email or ""):
            raise AuthError("a valid email address is required")
        probs = password_problems(password, username)
        if probs:
            raise AuthError("weak password: " + ", ".join(probs))
        if use_case not in USE_CASES:
            raise AuthError(f"use_case must be one of {list(USE_CASES)}")
        if deployment_target not in DEPLOY_TARGETS:
            raise AuthError(f"deployment_target must be one of {list(DEPLOY_TARGETS)}")
        first = self.count() == 0
        if first and self.store.meta_get("first_admin_created"):
            # deleting every user row must not hand the admin role to whoever registers next
            self.store.report_violation("users", "*", "user table emptied outside the agent")
            raise AuthError("the user table is empty although an administrator was registered before - possible "
                            "tampering; restore the database from a backup")
        if first:
            final_role = "admin"
        elif created_by is not None and created_by.can("manage_users"):
            final_role = role or "analyst"
        else:
            final_role = "viewer"           # self-registration: least privilege until promoted
        if final_role not in ROLES:
            raise AuthError(f"role must be one of {ROLES}")
        if self.store.query("SELECT 1 FROM users WHERE username = ?", (username,)):
            raise AuthError("username already registered")
        api_key = "edk_" + secrets.token_urlsafe(32)
        with self.store.tx():
            cur = self.store.execute(
                "INSERT INTO users (username, email, full_name, organization, role, use_case, deployment_target,"
                " password_hash, api_key_hash, created_at, consent_share, token_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,0)",
                (username, email, full_name, organization, final_role, use_case, deployment_target,
                 hash_password(password), _token_hash(api_key), time.time(), int(consent_share)))
            self.store.reseal_user(cur.lastrowid)
            if first:
                self.store.meta_set("first_admin_created", True)
            self.store.audit(created_by.username if created_by else username, "user_registered",
                             {"username": username, "role": final_role, "use_case": use_case,
                              "deployment_target": deployment_target, "organization": organization})
        user = self.get(username)
        assert user
        if consent_share:
            self._share_registration(user)
        return user, api_key

    def _share_registration(self, user: User) -> None:
        """Opt-in: send the registration profile (never credentials) to the operator's endpoint."""
        if not self.webhook_url:
            return
        body = json.dumps({"event": "eldoctor_registration", "username": user.username, "email": user.email,
                           "full_name": user.full_name, "organization": user.organization, "role": user.role,
                           "use_case": user.use_case, "deployment_target": user.deployment_target,
                           "ts": time.time()}).encode()
        try:
            req = urllib.request.Request(safe_url(self.webhook_url), data=body,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).close()  # noqa: S310 - operator-configured URL
            self.store.audit(user.username, "registration_shared", {"url": self.webhook_url.split("?")[0]})
        except Exception as exc:
            self.store.audit(user.username, "registration_share_failed", {"error": str(exc)})

    # ------------------------------------------------------------------ queries
    def _row(self, username: str) -> Optional[Dict[str, Any]]:
        rows = self.store.query("SELECT * FROM users WHERE username = ?", (username,))
        return rows[0] if rows else None

    def get(self, username: str) -> Optional[User]:
        """The user, only if its sealed record is intact (a role edited in the DB is never trusted)."""
        r = self._row(username)
        if not r or not self.store.user_row_ok(r):
            return None
        return User.from_row(r)

    def get_by_id(self, user_id: int) -> Optional[User]:
        rows = self.store.query("SELECT * FROM users WHERE id = ?", (int(user_id),))
        if not rows or not self.store.user_row_ok(rows[0]):
            return None
        return User.from_row(rows[0])

    def list(self) -> List[Dict[str, Any]]:
        rows = self.store.query("SELECT * FROM users ORDER BY id")
        out = []
        for r in rows:
            ok = self.store.keys.check_seal("user", self.store._user_fields(r), r.get("seal"))
            out.append({k: r[k] for k in ("id", "username", "email", "full_name", "organization", "role", "use_case",
                                          "deployment_target", "created_at", "last_login", "active")}
                       | {"integrity": "ok" if ok else "invalid"})
        return out

    def can_approve(self, username: str) -> Tuple[bool, str]:
        """Used by the agent right before executing an approved action: the approver must *still* exist,
        be active, have an intact record and hold the approve permission."""
        u = self.get(username)
        if not u:
            return False, f"unknown user or tampered account record {username!r}"
        if not u.can("approve"):
            return False, f"{username} (role {u.role}) lacks the approve permission"
        return True, ""

    def _update(self, username: str, sql: str, params: tuple, bump_tokens: bool = False) -> bool:
        with self.store.tx():
            cur = self.store.execute(sql, params)
            if cur.rowcount != 1:
                return False
            if bump_tokens:           # invalidates every token issued before (role change, disable)
                self.store.execute("UPDATE users SET token_version = token_version + 1 WHERE username = ?", (username,))
            r = self._row(username)
            self.store._reseal_user(r)
        return True

    def set_role(self, actor: User, username: str, role: str) -> None:
        if not actor.can("manage_users"):
            raise AuthError("only admins can change roles")
        if role not in ROLES:
            raise AuthError(f"role must be one of {ROLES}")
        target = self.get(username)
        if not target:
            raise AuthError("no such user")
        if target.role == "admin" and role != "admin":
            admins = self.store.query("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND active=1")[0]["n"]
            if admins <= 1:
                raise AuthError("cannot demote the last admin")
        self._update(username, "UPDATE users SET role = ? WHERE username = ?", (role, username), bump_tokens=True)
        self.store.audit(actor.username, "role_changed", {"username": username, "role": role,
                                                          "previous_role": target.role})

    def set_active(self, actor: User, username: str, active: bool) -> None:
        if not actor.can("manage_users"):
            raise AuthError("only admins can enable/disable users")
        if username == actor.username and not active:
            raise AuthError("you cannot disable yourself")
        if not self.get(username):
            raise AuthError("no such user")
        self._update(username, "UPDATE users SET active = ? WHERE username = ?", (int(active), username),
                     bump_tokens=not active)
        self.store.audit(actor.username, "user_enabled" if active else "user_disabled", {"username": username})

    def logout_everywhere(self, user: User) -> None:
        self._update(user.username, "UPDATE users SET last_login = last_login WHERE username = ?", (user.username,),
                     bump_tokens=True)
        self.store.audit(user.username, "sessions_revoked", {})

    # ------------------------------------------------------------------ authentication
    def authenticate(self, username: str, password: str) -> User:
        rows = self.store.query("SELECT * FROM users WHERE username = ?", (username,))
        if not rows:
            verify_password(password, hash_password("x", 1000))     # similar timing for unknown users
            self.store.audit(username, "login_failed", {"reason": "unknown user"})
            raise AuthError("invalid username or password")
        r = rows[0]
        now = time.time()
        if not self.store.user_row_ok(r):
            self.store.audit(username, "login_failed", {"reason": "account record failed its integrity check"})
            raise AuthError("account record failed its integrity check (modified outside El Doctor) - "
                            "ask an administrator")
        if r["locked_until"] and r["locked_until"] > now:
            raise AuthError(f"account locked, try again in {int(r['locked_until'] - now)}s")
        if not r["active"]:
            raise AuthError("account disabled")
        if not verify_password(password, r["password_hash"]):
            fails = r["failed_logins"] + 1
            locked = now + self.lock_minutes * 60 if fails >= self.lock_attempts else 0
            self.store.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                               (0 if locked else fails, locked, r["id"]))
            self.store.audit(username, "login_failed", {"failures": fails, "locked": bool(locked)})
            raise AuthError("invalid username or password" + (" - account locked" if locked else ""))
        self.store.execute("UPDATE users SET failed_logins = 0, locked_until = 0, last_login = ? WHERE id = ?",
                           (now, r["id"]))
        self.store.audit(username, "login", {})
        return User.from_row(r)

    def user_for_api_key(self, key: str) -> Optional[User]:
        rows = self.store.query("SELECT * FROM users WHERE api_key_hash = ? AND active = 1", (_token_hash(key),))
        if not rows or not self.store.user_row_ok(rows[0]):
            return None
        return User.from_row(rows[0])

    def rotate_api_key(self, user: User) -> str:
        key = "edk_" + secrets.token_urlsafe(32)
        self._update(user.username, "UPDATE users SET api_key_hash = ? WHERE id = ?", (_token_hash(key), user.id))
        self.store.audit(user.username, "api_key_rotated", {})
        return key
