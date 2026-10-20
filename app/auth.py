"""Password gate: one shared password, checked against a bcrypt hash, then a signed cookie.

SITE_PASSWORD_HASH unset means the gate is off (local development, tests). The cookie is
"<expiry>.<hmac>", keyed by SESSION_SECRET and bound to the hash, so changing the password
signs everyone out.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict, deque

import bcrypt

COOKIE = "progent_session"
MAX_AGE = 30 * 24 * 3600
FAIL_WINDOW_S, FAIL_LIMIT = 300, 5

# Without a configured secret, sessions last until the process restarts.
_fallback_secret = secrets.token_bytes(32)
_failures: dict[str, deque[float]] = defaultdict(deque)
_check_lock = asyncio.Lock()  # bcrypt at cost 14 is ~1s of CPU; check one at a time


def password_hash() -> str:
    return os.getenv("SITE_PASSWORD_HASH", "").strip()


def enabled() -> bool:
    return bool(password_hash())


def _sign(expiry: int) -> str:
    key = os.getenv("SESSION_SECRET", "").encode() or _fallback_secret
    msg = f"{expiry}.{password_hash()}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def issue() -> str:
    expiry = int(time.time()) + MAX_AGE
    return f"{expiry}.{_sign(expiry)}"


def valid(cookie: str | None) -> bool:
    if not cookie or "." not in cookie:
        return False
    expiry, sig = cookie.split(".", 1)
    if not expiry.isdigit() or int(expiry) < time.time():
        return False
    return hmac.compare_digest(sig, _sign(int(expiry)))


def locked_out(client: str) -> bool:
    q = _failures[client]
    while q and q[0] < time.time() - FAIL_WINDOW_S:
        q.popleft()
    return len(q) >= FAIL_LIMIT


async def check_password(client: str, password: str) -> bool:
    async with _check_lock:
        ok = await asyncio.to_thread(
            bcrypt.checkpw, password.encode()[:72], password_hash().encode())
    if ok:
        _failures.pop(client, None)
    else:
        _failures[client].append(time.time())
    return ok
