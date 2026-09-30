"""Single sign-on for reviewers and admins: OpenID Connect access tokens.

The service accepts, besides its API keys, a JWT issued by your identity provider (Keycloak, Azure
AD / Entra ID, Okta, Google...). The signature is checked against the provider's JWKS; the issuer,
audience and expiry are checked; a claim is mapped to a role and another to a tenant:

    server:
      oidc:
        issuer: https://sso.example.vn/realms/acme
        audience: guardrail
        jwks_url: https://sso.example.vn/realms/acme/protocol/openid-connect/certs
        roles_claim: realm_access.roles          # dotted path into the token
        role_map: {guardrail-admin: admin, guardrail-reviewer: reviewer, guardrail-app: client}
        tenant_claim: tenant
        name_claim: preferred_username

``jwks`` (the key set itself) may be given instead of ``jwks_url`` for air-gapped deployments.
Needs ``pip install "guardrail-rag-jev[sso]"``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

ROLE_RANK = {"client": 0, "reviewer": 1, "admin": 2}


@dataclass
class OidcConfig:
    issuer: str
    audience: str
    jwks_url: str | None = None
    jwks: dict[str, Any] | None = None
    roles_claim: str = "roles"
    role_map: dict[str, str] = field(default_factory=dict)
    tenant_claim: str | None = None
    name_claim: str = "preferred_username"
    algorithms: list[str] = field(default_factory=lambda: ["RS256", "ES256", "PS256"])
    leeway: int = 30

    def __post_init__(self) -> None:
        if not (self.jwks_url or self.jwks):
            raise ValueError("server.oidc needs jwks_url or jwks")
        bad = {r for r in self.role_map.values() if r not in ROLE_RANK}
        if bad:
            raise ValueError(f"server.oidc.role_map maps to unknown roles {sorted(bad)}")


class AuthError(Exception):
    pass


def claim(token: Mapping[str, Any], path: str | None) -> Any:
    """A claim by dotted path: ``realm_access.roles``."""
    if not path:
        return None
    value: Any = token
    for part in path.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


class OidcVerifier:
    def __init__(self, config: OidcConfig) -> None:
        try:
            import jwt  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ImportError('SSO needs PyJWT: pip install "guardrail-rag-jev[sso]"') from exc
        self.jwt = jwt
        self.config = config
        self._client = jwt.PyJWKClient(config.jwks_url, cache_keys=True) if config.jwks_url else None
        self._set = jwt.PyJWKSet.from_dict(config.jwks) if config.jwks else None

    def _key(self, token: str) -> Any:
        if self._client is not None:
            return self._client.get_signing_key_from_jwt(token).key
        kid = self.jwt.get_unverified_header(token).get("kid")
        for k in self._set.keys:  # type: ignore[union-attr]
            if kid is None or k.key_id == kid:
                return k.key
        raise AuthError("no key in the JWKS matches the token")

    def verify(self, token: str) -> dict[str, Any]:
        """The caller a valid token describes: role, name, tenant. Raises AuthError otherwise."""
        c = self.config
        try:
            payload = self.jwt.decode(
                token, self._key(token), algorithms=c.algorithms, audience=c.audience, issuer=c.issuer,
                leeway=c.leeway, options={"require": ["exp", "iss", "aud"]},
            )
        except AuthError:
            raise
        except Exception as exc:  # noqa: BLE001 - every token failure is a 401
            raise AuthError(f"invalid token: {exc}") from exc
        values = claim(payload, c.roles_claim)
        values = [values] if isinstance(values, str) else list(values or [])
        roles = [c.role_map[v] for v in values if v in c.role_map]
        if not roles:
            raise AuthError("the token carries no role this service knows")
        tenant = claim(payload, c.tenant_claim)
        return {
            "role": max(roles, key=ROLE_RANK.__getitem__),
            "name": str(claim(payload, c.name_claim) or payload.get("sub") or "sso-user"),
            "tenant": str(tenant) if tenant else None,
        }
