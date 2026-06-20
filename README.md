# snapdragon-auth-core

Shared **stateful** Snapdragon auth core — the account/session/MFA/Casdoor-admin
infrastructure used by BOTH `snapdragon-user-bff-api` (login + OIDC token-handler) and
`snapdragon-admin-bff-api` (admin features that read accounts/allowlist/suspension and
drive MFA step-up).

## Why a separate module (not `snapdragon-commons`)
`snapdragon-commons` is the **light, stateless** security/tenancy jar that the **gateway**
and every BFF depend on (Casdoor JWT authorities, issuer→domain registry, `ApiException`).
This core is the opposite — reactive **R2DBC** entities/repos, Casdoor-admin **WebClient**,
AES-256-GCM crypto, **TOTP/WebAuthn** — so folding it into commons would drag r2dbc + the
Casdoor/MFA stack onto the gateway's classpath and risk its Boot-4 pin. So:

```
snapdragon-commons   (light; stateless)      <- gateway + ALL services
snapdragon-auth-core (heavy; r2dbc/casdoor/mfa) <- user-bff + admin-bff ONLY
   └─ depends on snapdragon-commons            (no cycle)
```

## Data ownership
The account/session/allowlist/MFA **tables stay in `admin-bff-db`** (admin-bff has ~10
synchronous readers; the mutual-DB-denial NetworkPolicy forbids cross-DB hops). admin-bff
wires the R2DBC-backed stores against admin-bff-db and exposes a thin `/bff/internal/**`
account+session API (mTLS + `X-Internal-Token`); user-bff owns the login/OIDC **endpoints**
and reaches the data via that internal API.

## Status (incremental extraction)
- ✅ `account/` — Account, AccountRow(+repo), AccountStore, Allowlist(+repo),
  BffSession(+repo), NamespaceGrant(+repo). Self-contained; builds against commons + r2dbc.
- ⏳ next: `casdoor/`, `mfa/`, `config/` (session-cookie + internal-token filters),
  `provision/`, `suspension/`, `profile/`, `reserved/`, `web/dto/` — per the extraction
  blueprint. admin-bff + user-bff then adopt this jar.

Build: `./mvnw -o clean package` (resolves snapdragon-parent + snapdragon-commons 2.0.0 from `~/.m2`).
