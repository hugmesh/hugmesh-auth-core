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

## Where this fits in the auth model
Casdoor is the SSO IdP. `login-ui` runs a Casdoor OIDC authorization-code (PKCE) redirect;
**user-bff** does the server-side code→token exchange and holds per-session JWT
custody/refresh. The browser only ever holds an **opaque `bff_`-prefixed session** — the
user never sees their own Casdoor JWT. The gateway is a pure Casdoor-JWT OAuth2 resource
server: a pre-security exchange filter swaps `bff_` → the internal custody JWT, then the
gateway's JWT validation + the data-driven `GatewayRouteAccessFilter`
(`gateway_route_access` Postgres table is the source of truth) run unchanged
(ADMIN/GAME-MASTER bypass within own domain, SUPERADMIN cross-domain).

This jar is the **shared stateful substrate** behind that flow: the account/session/MFA
stores and Casdoor-admin client that user-bff (login/session custody) and admin-bff
(account reads + MFA step-up) both build on. Login/session/account logic is being
**relocated from admin-bff to user-bff**; the reusable pieces land here so both BFFs share
one implementation while the account/session **data** continues to live in admin-bff-db.

## Status (incremental extraction)
- ✅ `account/` — Account, AccountRow(+repo), AccountStore, Allowlist(+repo),
  BffSession(+repo), NamespaceGrant(+repo). Self-contained; builds against commons + r2dbc.
- ⏳ next: `casdoor/`, `mfa/`, `config/` (session-cookie + internal-token filters),
  `provision/`, `suspension/`, `profile/`, `reserved/`, `web/dto/` — per the extraction
  blueprint. admin-bff + user-bff then adopt this jar.

Build: `./mvnw -o clean package` (resolves snapdragon-parent + snapdragon-commons 2.0.0 from `~/.m2`).

## Current State
- **Version 2.0.0** on the unified Snapdragon ecosystem baseline: **Spring Boot 4.0.2 /
  Spring Cloud 2025.1 / Java 21**, inherited via `snapdragon-parent` (metapom) **2.0.0**.
- Depends on `snapdragon-commons` **2.0.0** (stateless security/tenancy). **No cycle** —
  commons does not depend on this core.
- **Consumers: `user-bff` and `admin-bff` only.** The gateway depends on commons, NOT on
  this jar (keeping r2dbc/casdoor/mfa off the gateway classpath, per the rationale above).
- Reactive throughout: **Spring Data R2DBC** repositories (no raw SQL strings / inline
  `@Query`), matching the org data-access standard. Crypto via BouncyCastle
  (AES-256-GCM); MFA via webauthn4j (WebAuthn) + TOTP.
- **Extraction in progress**: the `account/` package is landed and self-contained; the
  remaining packages (`casdoor/`, `mfa/`, `config/`, `provision/`, `suspension/`,
  `profile/`, `reserved/`, `web/dto/`) are still being extracted from admin-bff as login
  relocates to user-bff.
- **No `spring.cloud.gateway.*` route config lives here** — this is a library, not a
  gateway; the SCG-5 route-namespace move
  (`spring.cloud.gateway.routes` → `spring.cloud.gateway.server.webflux.routes`) is a
  gateway/generator concern and does not touch this module.
- CI is **GitLab** (no GitHub Actions). Single `main` branch; no in-flight feature
  branches or open PRs at time of writing.

## Roadmap
This jar advances in lockstep with the platform auth roadmap; the next increments are:
- **Finish the extraction**: move `casdoor/`, `mfa/`, `config/` (session-cookie +
  internal-token filters), `provision/`, `suspension/`, `profile/`, `reserved/`,
  `web/dto/` here, then have admin-bff + user-bff adopt the jar (login/session logic fully
  relocated admin-bff → user-bff).
- **SSO end-to-end + e2e**: support the live Casdoor OIDC (PKCE) → opaque `bff_` session
  flow and the gateway exchange-filter path, with end-to-end tests.
- **MFA**: WebAuthn + TOTP + recovery, per-role defaults and step-up — the shared MFA
  store/verifier infrastructure for both BFFs.
- Track the wider platform roadmap where it touches account/session/MFA: multi-tenancy
  superadmin, device-license registry, desktop app governance (SSO sudo), and OWASP
  pen-test + nuclei in CI.

_Grounded in the Snapdragon-Systems current-state brief (2026-06-20). Features beyond the
brief and the prior README are intentionally not invented here._
