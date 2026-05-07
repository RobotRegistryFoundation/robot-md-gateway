from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from fastapi import Header, HTTPException

Tier = Literal["read", "actuate"]


@dataclass(frozen=True)
class AuthContext:
    caller_id: str
    tier: Tier
    api_key: str

    @property
    def api_key_fingerprint(self) -> str:
        return hashlib.sha256(self.api_key.encode()).hexdigest()[:12]


@dataclass(frozen=True)
class _BearerEntry:
    token: str
    tier: Tier
    caller_id: str


class BearerStore:
    def __init__(self, entries: list[_BearerEntry]) -> None:
        self._by_token = {e.token: e for e in entries}

    @classmethod
    def from_yaml(cls, path: Path) -> BearerStore:
        data = yaml.safe_load(path.read_text()) or []
        entries = [
            _BearerEntry(token=row["token"], tier=row["tier"], caller_id=row["caller"])
            for row in data
        ]
        if not entries:
            raise ValueError(f"{path} has no bearer entries")
        for e in entries:
            if e.tier not in ("read", "actuate"):
                raise ValueError(f"invalid tier {e.tier!r} for caller {e.caller_id}")
        return cls(entries)

    def resolve(self, token: str) -> _BearerEntry | None:
        return self._by_token.get(token)


def _parse_bearer(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing Authorization header")
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        raise HTTPException(status_code=401, detail="Authorization must be Bearer <token>")
    return authorization.removeprefix(prefix).strip()


def _validate_api_key(key: str | None) -> str:
    if not key:
        raise HTTPException(
            status_code=401,
            detail="missing X-Anthropic-Api-Key header (BYOK required)",
        )
    if not key.startswith("sk-ant-"):
        raise HTTPException(status_code=401, detail="invalid Anthropic API key format")
    return key


def make_auth_dep(store: BearerStore):
    def dep(
        authorization: str | None = Header(default=None),
        x_anthropic_api_key: str | None = Header(default=None),
    ) -> AuthContext:
        token = _parse_bearer(authorization)
        entry = store.resolve(token)
        if entry is None:
            raise HTTPException(status_code=401, detail="unknown bearer")
        api_key = _validate_api_key(x_anthropic_api_key)
        return AuthContext(
            caller_id=entry.caller_id,
            tier=entry.tier,
            api_key=api_key,
        )

    return dep


def load_bearer_store_from_env() -> BearerStore:
    path = os.environ.get("ROBOT_MD_BEARERS_FILE")
    if not path:
        raise RuntimeError("ROBOT_MD_BEARERS_FILE not set")
    return BearerStore.from_yaml(Path(path))


class RRFResolverFromEnv:
    """Resolves a kid → public-key PEM via the RRF v2 API.

    Reads OPENCASTOR_OPS_RRF_URL (default https://robotregistryfoundation.org).
    Caches lookups in process memory for the gateway's lifetime; revocation
    polling is added in Plan 6 (RR-001).
    """

    def __init__(self, base_url: str) -> None:
        self._base = base_url.rstrip("/")
        self._cache: dict[str, bytes] = {}

    @classmethod
    def from_env(cls) -> RRFResolverFromEnv:
        default = "https://robotregistryfoundation.org"
        return cls(os.environ.get("OPENCASTOR_OPS_RRF_URL", default))

    def resolve_public_key_pem(self, kid: str) -> bytes | None:
        if kid in self._cache:
            return self._cache[kid]
        import json
        import urllib.request
        url = f"{self._base}/v2/keys/{kid}"
        # Cloudflare in front of robotregistryfoundation.org rejects requests
        # with the default Python-urllib/* User-Agent (HTTP 403). Send a
        # distinct, identifying UA the WAF allows. Includes the gateway version
        # so prod log analysis can correlate kid-resolution patterns with
        # gateway releases.
        try:
            from . import __version__ as _ver  # type: ignore[attr-defined]
        except Exception:
            _ver = "unknown"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"robot-md-gateway/{_ver} (+kid-resolver)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    return None
                payload = json.loads(resp.read())
                pem = payload.get("public_key_pem", "").encode("utf-8")
                if pem:
                    self._cache[kid] = pem
                return pem or None
        except Exception:
            return None
