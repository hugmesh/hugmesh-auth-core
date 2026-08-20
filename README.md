# hugmesh-auth-core

Shared **stateful** HugMesh auth core — the account/session/MFA/Casdoor-admin
infrastructure used by BOTH `hugmesh-user-bff-api` (login + OIDC token-handler) and
`hugmesh-admin-bff-api` (admin features that read accounts/allowlist/suspension and
drive MFA step-up).

## Why a separate module (not `hugmesh-commons`)
`hugmesh-commons` is the **light, stateless** security/tenancy jar that the **gateway**
and every BFF depend on (Casdoor JWT authorities, issuer→domain registry, `ApiException`).
This core is the opposite — reactive **R2DBC** entities/repos, Casdoor-admin **WebClient**,
AES-256-GCM crypto, **TOTP/WebAuthn** — so folding it into commons would drag r2dbc + the
Casdoor/MFA stack onto the gateway's classpath and risk its Boot-4 pin. So:

```
hugmesh-commons   (light; stateless)      <- gateway + ALL services
hugmesh-auth-core (heavy; r2dbc/casdoor/mfa) <- user-bff + admin-bff ONLY
   └─ depends on hugmesh-commons            (no cycle)
```

## Data ownership
The account/session/allowlist/MFA **tables stay in `admin-bff-db`** (admin-bff has ~10
synchronous readers; the mutual-DB-denial NetworkPolicy forbids cross-DB hops). admin-bff
wires the R2DBC-backed stores against admin-bff-db and exposes a thin `/bff/internal/**`
account+session API (mTLS + `X-Internal-Token`); user-bff owns the login/OIDC **endpoints**
and reaches the data via that internal API.

## Where this fits in the auth model
Casdoor is the SSO IdP. `login-ui` renders a **native username/password (+MFA)** form and
POSTs to `/bff/login`; **user-bff** generates PKCE+state **server-side** and calls the
**internal** Casdoor `/api/login`, then exchanges the code and holds per-session JWT
custody/refresh. The browser is **never redirected to Casdoor** and only ever holds an
**opaque `bff_`-prefixed session** — the user never sees their own Casdoor JWT. The gateway
is a pure Casdoor-JWT OAuth2 resource server: a pre-security exchange filter swaps `bff_` →
the internal custody JWT, then the
gateway's JWT validation + the data-driven `GatewayRouteAccessFilter`
(`gateway_route_access` Postgres table is the source of truth) run unchanged
(ADMIN/GAME-MASTER bypass within own domain, SUPERADMIN cross-domain).

This jar is the **shared stateful substrate** behind that flow: the account/session/MFA
stores and Casdoor-admin client that user-bff (login/session custody) and admin-bff
(account reads + MFA step-up) both build on. Login/session/account logic is being
**relocated from admin-bff to user-bff**; the reusable pieces land here so both BFFs share
one implementation while the account/session **data** continues to live in admin-bff-db.

### Native-login sequence

```mermaid
sequenceDiagram
    participant Browser
    participant LoginUI as login-ui
    participant UserBFF as user-bff (auth-core)
    participant Casdoor
    participant Gateway as gateway
    participant AdminBFF as admin-bff (auth-core)

    Browser->>LoginUI: username + password (+ MFA)
    LoginUI->>UserBFF: POST /bff/login
    UserBFF->>UserBFF: generate PKCE verifier and state
    UserBFF->>Casdoor: internal POST /api/login
    Casdoor-->>UserBFF: authorization code
    UserBFF->>Casdoor: OidcExchangeClient redeems code for tokens
    Casdoor-->>UserBFF: id_token, access_token, refresh_token
    UserBFF->>UserBFF: AccountStore.ensureAccount syncs Casdoor roles
    UserBFF->>UserBFF: AccountStore.newSession, stampCustody via BffCustodyCipher
    UserBFF-->>Browser: opaque bff_ session (cookie or bearer)

    Browser->>Gateway: request carrying the bff_ session
    Gateway->>Gateway: BffSessionAuthFilter authenticates the session
    Gateway->>AdminBFF: exchange filter swaps bff_ for the internal custody JWT
    AdminBFF->>AdminBFF: BffCookieAuthenticationWebFilter resolves AccountStore.sessionOfToken
    AdminBFF-->>Gateway: response
    Gateway-->>Browser: response
```

The browser only ever holds the opaque `bff_` value; every Casdoor/custody token stays
server-side, encrypted at rest by `BffCustodyCipher` when custody is stamped. `login-ui`,
`gateway`, and `Casdoor` itself live outside this repo — this diagram traces where
auth-core's own classes (`OidcExchangeClient`, `AccountStore`,
`BffCookieAuthenticationWebFilter`) sit in that cross-service flow.

## Status (extraction landed)
- ✅ `account/` — Account, AccountRow(+repo), AccountStatus, AccountStore, Allowlist(+repo),
  BffSession(+repo), NamespaceGrant(+repo). Self-contained; builds against commons + r2dbc.
- ✅ `casdoor/` — Casdoor-admin client/config, OIDC token-exchange client (`OidcExchangeClient`,
  optionally routed through gated outbound mTLS via `OidcExchangeClientSsl`), BFF-custody
  cipher (`BffCustodyCipher`), MFA challenge/step-up services, raw-JWT refresh.
- ✅ `mfa/` — TOTP, WebAuthn (webauthn4j), recovery codes, enrollment, secret cipher, the
  R2DBC factor/credential/challenge rows + repositories, and `MfaPreconditionBootGuard`
  (see **MFA precondition startup check** below).
- ✅ `config/` — session-cookie + internal-token web filters, the internal-surface boot guard,
  and `BffCookieAuthenticationWebFilter` (bridges an opaque `bff_` session into a real Spring
  Security `Authentication` for a consumer's own `hasAnyRole()`/`.authenticated()` gates —
  today wired for admin-bff only, see Known Gaps).
- ✅ `provision/` (gateway revocation client), `reserved/` (reserved-name gate),
  `username/` (federation username gate), `web/dto/` (login/register/MFA request DTOs).
- All packages from the extraction blueprint have landed; admin-bff + user-bff adopt this jar.

### MFA precondition startup check

`mfa/MfaPreconditionBootGuard` detects the MFA configurations that are silently broken or silently
unrecoverable, and by **default reports them as one loud `WARN` and lets the application start**.
It aborts the boot (throwing from `afterSingletonsInstantiated`, the same mechanism as
`config/InternalSurfaceBootGuard`) **only** when an operator explicitly opts in with
`app.mfa.preconditions.fail-fast=true` (env `APP_MFA_PRECONDITIONS_FAIL_FAST`, default `false`).

| Precondition | Reported when | Consequence if left unfixed |
| --- | --- | --- |
| `app.mfa.factor-key` (env `APP_MFA_FACTOR_KEY`) | MFA enabled and no usable key | The key gates the TOTP cipher **and** the recovery-code HMAC, but **not** WebAuthn — so MFA arms as WebAuthn-only with TOTP enroll and recovery-code generation both 503ing, and a user who loses their passkey is locked out with no self-service way back in (an operator must clear their factors by hand). |
| `app.mfa.webauthn.rp-id` (env `APP_MFA_WEBAUTHN_RP_ID`) | MFA enabled, **no dev profile**, and the RP ID is absent or a loopback host | It silently defaults to `localhost`, so every passkey registers against the wrong Relying Party and no ceremony can ever succeed. |
| `app.mfa.webauthn.origins` (env `APP_MFA_WEBAUTHN_ORIGINS`) | MFA enabled, **no dev profile**, and every allowlisted origin is loopback | It silently defaults to `https://localhost`, so the ceremony rejects every real browser origin. |

**Why WARN-by-default and not fail-fast-by-default.** These are not hypothetical states — they are
*tolerated* states in the shipped deployment, so making them fatal by default would convert a
degradation into an outage:

- hugmesh-generator `specs/cluster/manifests/admin-bff-api/deployment.yaml` sets
  `APP_CASDOOR_MFA_ENABLED: "true"` (MFA is **armed** in-cluster) and sources `APP_MFA_FACTOR_KEY`
  from an External-Secrets `secretKeyRef`. Historically that ref was marked `optional: true`
  ("*so the pod still starts if the Secret is somehow absent*"); the 2.4.2 release chain drops
  that (generator `fix/mfa-factor-key-required`), so in-cluster a genuinely absent Secret now
  blocks pod start at the Kubernetes layer (`CreateContainerConfigError`) before this guard ever
  runs. The guard still matters for every OTHER misconfiguration shape — key present but the
  WebAuthn properties absent, compose, bare-metal runs — which is exactly the degraded-but-running
  band below.
- The local compose stack (`tests/stack/compose.local.yaml`) runs MFA on with **neither** WebAuthn
  property set, and its `dev` profile is only the `ADMIN_BFF_PROFILES` default.

admin-bff-api is the **only** consumer that component-scans `net.hugmesh.authcore` (its
`@SpringBootApplication(scanBasePackages = …)`), and it is the admin/superadmin control plane plus
the gateway's cookie→JWT `POST /bff/internal/session/exchange` leg. Throwing on an absent ESO
secret would therefore CrashLoopBackOff that whole plane on a fresh cluster bring-up, on a new
brand/tenant where `gen-cluster-secrets` was not re-run, or on a Vault path typo — locking
operators out of the plane they would use to fix it. So the default is to *tell* them, precisely
and unmissably (`*** MFA MISCONFIGURED ***`, every property and env var named, the consequence
spelled out, and the opt-in named), and keep serving. Turning it fatal is a per-deployment
decision; the k8s-layer half of the sequencing — dropping `optional: true` from that
`secretKeyRef` — ships in the same release chain as 2.4.2, so the fully-absent-Secret case is
already fronted by the scheduler in-cluster.

No actuator health indicator is offered: this module has **no** `spring-boot-actuator` dependency
and no health-contributor precedent, and a shared auth jar is the wrong place to acquire one.

Two test classes cover it: `MfaPreconditionBootGuardTest` (the decision logic, including a
`ListAppender` capture so "it WARNs loudly" is a real assertion rather than a claim) and
`MfaPreconditionBootGuardContextTest` (a **real** `AnnotationConfigApplicationContext.refresh()`,
because whether a pod comes up is decided by `refresh()` completing, not by a method call). The
class is **released in 2.4.2** — the version was bumped precisely because the GitLab
`deploy:maven` job re-runs `deploy` at whatever version the pom holds on every `main` merge, so
leaving the pom at 2.4.1 would leave every later merge re-deploying over a coordinate consumers
already pin. A consumer
picks the guard up by repointing its dependency to 2.4.2. The `optional: true` drop on the
`admin-bff-mfa` `secretKeyRef` ships in the same release chain (generator
`fix/mfa-factor-key-required`, pinned by that repo's `[mfa-factor-key]` manifest-integrity
check), so the missing-secret case surfaces at the Kubernetes layer with a clear reason rather
than as a running-but-degraded pod; turning this guard *fatal*
(`app.mfa.preconditions.fail-fast=true`) remains a separate per-deployment decision for the
misconfiguration shapes the scheduler cannot see.

Every check is behind `app.casdoor.mfa.enabled` (**default `false`** in every consumer's
`application.yml`), so an MFA-off deployment stays completely silent — that invariant is the first
thing the test class asserts, together with the fact that arming the opt-in while MFA is off is
still a no-op. The bean is also absent under the `test` profile.

**Dev detection** is "`dev` or `test` is in `Environment.getActiveProfiles()`" — exactly the profile
names in `InternalSurfaceBootGuard`'s `@Profile("!dev & !test")` predicate, so this library has one
dev rule, not two (a test asserts the set is exactly those two; `local` is deliberately **not**
included, because no manifest, compose service or `application-*.yml` in this fleet activates such
a profile). The only difference is bean *presence*: this bean is `@Profile("!test")` rather than
`!dev & !test`, because it still has something useful to say under `dev` — the local compose stack
runs `SPRING_PROFILES_ACTIVE=casdoor,dev` and sets no RP ID, so it gets a dev-specific WARN and is
never counted as a problem (not even under the opt-in, so arming fail-fast fleet-wide cannot break
a local stack); the cluster runs `casdoor,clickhouse` and does set a real RP ID. An unprofiled
deployment is treated as NOT dev — the safe direction for a passkey RP ID. mDNS `*.local` hosts are
deliberately **not** classified as loopback (a LAN node may legitimately be `foo.local`); RFC-6761
`*.localhost` is.

Build: `./mvnw -o clean package` (resolves hugmesh-parent 2.8.0 + hugmesh-commons 2.1.0
from `~/.m2`) — runs the full test suite as part of `package`. A handful of MFA-repo data-slice
tests need a real Postgres via Testcontainers, so a local run also needs Docker (or `-Dtest=
'!*PostgresTest'` to skip just those). `./mvnw -o clean verify` additionally runs PMD +
Checkstyle + SpotBugs (see Current State / Known Gaps for their actual current enforcement
status). Re-verified 2026-07-30: `clean test` with Docker available — the **whole** suite green
(`Failures: 0, Errors: 0, Skipped: 0`; without Docker the Postgres slices are the only thing that
drops out), 0 Checkstyle/PMD violations, BUILD
SUCCESS. Re-verified 2026-08-20: `clean verify` (which the `hugmesh-parent` 2.8.0 bump put in
genuine fail mode via `failOnError`, not the no-op `failOnViolation` the historical 2.7.0 config
used) is **BUILD SUCCESS** too — 450 tests green, `BugInstance size is 0` — since the repo-local
`spotbugs/exclude-filter.xml` triaged the 8 `EI_EXPOSE_REP2` findings (see Known Gaps).

## Current State
- **Version 2.5.0** on the unified HugMesh ecosystem baseline: **Spring Boot 4.0.7 /
  Spring Cloud 2025.1.2 / Java 25 LTS** (eclipse-temurin:25), inherited via
  `hugmesh-parent` (metapom) **2.8.0** (which runs **PMD + Checkstyle + SpotBugs** during
  `verify` and pins **testcontainers 2.0.5**; PMD and Checkstyle fail on violation, and — as
  of the 2.8.0 bump — SpotBugs is genuinely in fail mode too (via `failOnError`); see Known
  Gaps for how this module's 8 findings were triaged).
- Depends on `hugmesh-commons` **2.1.0** (stateless security/tenancy; #23 pinned the
  real coordinate — a `2.7.0` commons was never published). **No cycle** —
  commons does not depend on this core.
- **Consumers: `user-bff` and `admin-bff` only.** The gateway depends on commons, NOT on
  this jar (keeping r2dbc/casdoor/mfa off the gateway classpath, per the rationale above).
- Reactive throughout: **Spring Data R2DBC** repositories (no raw SQL strings / inline
  `@Query`), matching the org data-access standard. Crypto via BouncyCastle
  (AES-256-GCM); MFA via **webauthn4j 0.31.7** (WebAuthn) + TOTP. webauthn4j 0.31 migrated
  internally to Jackson 3 (`tools.jackson`), aligned with this module's Boot 4 / Jackson 3
  stack; `WebAuthnService` uses the `CredentialRecord` API.
- **BFF JWT custody (2.1.0)**: `BffSession` carries the OIDC-token-custody columns
  (`access_token_enc` / `refresh_token_enc` / `access_token_expires_at` /
  `custody_updated_at`, admin-bff band-180; alongside the changeset-150 MFA columns
  `mfa_satisfied` / `mfa_satisfied_at` / `amr`). These are **NULLABLE and never written at
  session mint** — `AccountStore.newSession` leaves them null, so a pre-band-180 (2.0.0)
  consumer reads them as null. The custody passthrough lands as `AccountStore.stampCustody`
  / `clearCustody` (delegating to `BffSessionRepository`) plus `AccountStore.sessionRow`,
  which the dark custody endpoints use to stamp/clear/read per-session encrypted tokens for
  the opaque `bff_`-session custody model.
- **List a user's sessions by account (2.2.0)**: `AccountStore.sessionsForAccount` plus the
  `BffSessionRepository.findByAccountIdAndExpiresAtAfterOrderByCreatedAtDesc` derived finder
  back the "my active sessions" read for the session-management UI. The `accountId` MUST be
  derived **server-side** from the validated principal (never a request parameter — a user
  may only list THEIR OWN sessions); expired rows are filtered at the DB (`expires_at >
  now()`), newest-first, and projected to `BffSessionRow` so callers never touch the entity's
  custody/MFA internals.
- **Domain-scoped allowlist + namespace grants (changeset 220)**: `Allowlist` and
  `NamespaceGrant` now carry a `domain` field (composite PK `provider/handle/domain` and
  `grantee/namespace/domain` respectively) closing a BOLA/IDOR gap where a brand-X admin
  could read/write/delete brand-Y's invite or namespace-grant rows. `AllowlistRepository` /
  `NamespaceGrantRepository` expose domain-scoped finders, deletes, and a 3-arg
  `insertIfAbsent(..., domain)`; existing rows back-fill to `"default"`. The registration-gate
  read is domain-scoped too (`existsByProviderAndHandleAndDomain`, surfaced as
  `AccountStore.isEmailInvited(email, domain)` / `isDiscordInvited(handle, domain)`); the
  unscoped `existsByProviderAndHandle` overloads are **deprecated** and kept only for callers
  not yet threaded with a requesting domain (see Known Gaps below).
- **Subject-level revocation (`GatewayRevocationClient.revokeSubject`)**: writes a
  `subject:<casdoorSub>` key so the gateway's `RevocationGatewayFilter` denies a user's
  live custody JWT immediately on role-revoke, instead of waiting out its natural TTL
  (default 1 h). Same best-effort / `broker.gateway-revocation.enabled`-gated pattern as the
  existing coarse homeserver-ban revocation (`revokeCoarse` / `clearCoarse`).
- **DB-generated MFA UUID PKs (2.3.0)**: the `mfa_factor` / `mfa_recovery_code` /
  `webauthn_credential` / `webauthn_challenge` `id` columns are NO LONGER minted in Java —
  the production columns carry a `DEFAULT (gen_random_uuid())::text` (admin-bff changeset
  151/152), so the enroll INSERT OMITS `id` and appends `RETURNING id` to read the
  database-generated UUID back (a plain non-`@Modifying` `@Query` returning `Mono<String>`).
  The MFA-repo data-slice tests run on **real Postgres** (commons `PostgresTestSupport` /
  Testcontainers), since `gen_random_uuid()` and `INSERT ... RETURNING` are Postgres features
  H2 does not honour.
- **Code-side-lens MFA enums**: `FactorType` (`TOTP`|`WEBAUTHN`, the `mfa_factor.type`
  discriminator) and `CeremonyType` (registration|assertion, the
  `webauthn_challenge.ceremony_type` discriminator) wrap the app-owned closed vocabularies as
  `@JsonValue`/`@JsonCreator` lenses over the persisted String columns — R2DBC mapping stays
  byte-identical and the legacy `TYPE_TOTP`/`TYPE_WEBAUTHN` constants delegate to the enum.
- **Casdoor role sync on every login (2.3.1)**: `AccountStore.ensureAccount(provider, handle,
  roles)` SYNCS a non-empty `roles` list onto the account row on every call, not just at
  creation — a Casdoor role grant/revoke now reaches the BFF session on the very next login
  instead of freezing at whatever was true the first time the account was provisioned. The
  null/empty-roles path delegates entirely to the original 2-arg `ensureAccount(provider,
  handle)`, which stays a pure read for an existing account (never rewrites it).
- **Service-local `bff_` session bridge (2.3.2)**: `BffCookieAuthenticationWebFilter`
  (`config/`) resolves an opaque `bff_` session directly via `AccountStore` and populates a
  real Spring Security `Authentication`, so a consumer's own `hasAnyRole()`/`.authenticated()`
  gates (previously only reachable by a real Casdoor JWT, since `oauth2ResourceServer().jwt()`
  is correctly inert to an opaque token) also see native-login sessions. Only works for a
  service with a LOCAL `AccountStore` bean (today: admin-bff only) — user-bff/mod-bff/
  federation-api need a different, HTTP-based bridge (see Known Gaps).
- **Gated outbound mTLS for the OIDC token exchange**: `OidcExchangeClientSsl` optionally
  routes `OidcExchangeClient`'s Casdoor token-endpoint calls (the PKCE code/refresh leg, which
  carries `client_secret` + tokens) through client-cert + cluster-CA mTLS, mirroring
  user-bff's `FederationHttpClientSsl` (same `hugmesh.mtls.client.*` flag/property names).
  Default OFF; degrades to plain HTTP with a warning if the gate is on but the keystore file
  is absent, so a misconfigured pod never crash-loops on boot.
- **Reserved-username canonical sync (2.3.3, extended in 2.4.1)**: `ReservedNames.RESERVED`
  carries the full 82-label canonical set (`reserved/ReservedNames.java`), kept byte-for-byte
  in sync with the independent copies in `hugmesh-federation-api` and `hugmesh-actions`.
  2.4.1 reconciled canonical `reserved-prefixes.yaml` revisions 7-9: `hmdm` + `attest`
  (Headwind MDM / AttestationServer tailnet superadmin-gateway route prefixes) and
  `character-forge` + `games-character-forge` + `games-shadows-of-the-net` (the Character
  Forge 3D fe-gateway route + the hugmesh.games wasm slugs of the XR-chat track).
- **MFA hardening release (2.4.2)**: `WebAuthnService.newChallengeBase64Url` now draws the
  WebAuthn challenge as **32 CSPRNG bytes** from a shared `SecureRandom` (`CHALLENGE_BYTES = 32`;
  previously `new DefaultChallenge()`, whose no-arg form in webauthn4j 0.31.7 is
  `UUID.randomUUID()` packed into 16 bytes — that cleared the W3C "at least 16 bytes" floor, so
  this is hardening + doc-drift repair, not a live-hole fix); `MfaPreconditionBootGuard` (see the
  startup-check section above) ships with its `app.mfa.preconditions.fail-fast` opt-in
  (WARN-by-default unchanged); and the recovered MFA ceremony tests are verified non-vacuous
  (PRs #39/#40/#41). The bump itself is load-bearing: the `deploy:maven` job re-runs `deploy` at
  whatever version the pom holds on every `main` merge, so the moment #39/#40/#41 merged, 2.4.1
  stopped being a trustworthy immutable coordinate — 2.4.2 restores a meaningful pin. (Whether
  each post-2.4.1 merge's re-publish actually *landed* depends on the deploy job's `verify` leg,
  which failed on the 8 SpotBugs findings below until they were triaged; the coordinate is
  compromised either way for merges made while it was red.)
- **Identity-fold correctness fixes (2.3.4)**: `CasdoorAdminClient#usernameOf` now strips a
  trailing `@...` suffix for EVERY provider (previously only `google`), closing a bug where a
  native `casdoor:` account whose handle is email-shaped (`casdoor:alice@gmail.com`) minted an
  `@`-bearing Casdoor role-member id that could never match a real role membership; and
  `AccountStore.idFor` (plus both `ensureAccount` overloads) now folds the write-side account
  id via `trim() + toLowerCase(Locale.ROOT)`, matching the gateway's equivalent read-side fold.
- **Extraction landed**: all packages from the blueprint — `account/`, `casdoor/`, `mfa/`,
  `config/` (session-cookie + internal-token filters + boot guard + the service-local `bff_`
  bridge), `provision/`, `reserved/`, `username/`, `web/dto/` — have been extracted from
  admin-bff; admin-bff + user-bff adopt this jar as login relocates to user-bff.
- **No `spring.cloud.gateway.*` route config lives here** — this is a library, not a
  gateway; the SCG-5 route-namespace move
  (`spring.cloud.gateway.routes` → `spring.cloud.gateway.server.webflux.routes`) is a
  gateway/generator concern and does not touch this module.
- CI is **GitLab** (no GitHub Actions). Single `main` branch; no in-flight feature
  branches or open PRs at time of writing.

## Known Gaps / TODO
Verified against the current code (no invented gaps):
- **Registration gate: the scoped check exists, the BFF call sites are not migrated yet** —
  this jar now offers the domain-scoped gate (`AllowlistRepository
  .existsByProviderAndHandleAndDomain`, `AccountStore.isEmailInvited(email, domain)` /
  `isDiscordInvited(handle, domain)`) and **deprecates** the unscoped overloads. Until the
  consumers migrate, the cross-brand hole stays open at THEIR call sites: admin-bff's
  `AuthController.registerGoogle` / `registerDiscord` and
  `InternalAccountController#ensureAccount` still call the deprecated unscoped overloads,
  because a *pre-authentication* registration request has no validated JWT and therefore no
  `PrincipalDomain` — deciding where that domain comes from (request host, an explicit body
  field, or a per-deployment property) is a BFF-side decision, not a library one.
- **Gateway revocation writes are a no-op unless explicitly enabled** —
  `GatewayRevocationClient.revokeCoarse` / `revokeSubject` / `clearCoarse` all short-circuit
  to a logged STUB (`Mono.empty()`) when `broker.gateway-revocation.enabled` is `false`
  (the default), so in dev/test/CI (and any prod deployment that hasn't flipped the flag)
  the fast-path JWT/homeserver-token revocation never reaches the gateway — only the
  authoritative Postgres row (`access_suspension`) is written
  (`GatewayRevocationClient.java:49-53,168-196`).
- **MFA BFF wiring not yet complete** — per the Roadmap below, the MFA store/verifier
  substrate (TOTP, WebAuthn, recovery codes) is fully landed here, but per-role MFA
  defaults, step-up enforcement in admin-bff, and the Casdoor MFA bridge for the opaque
  `bff_`-session flow are still outstanding BFF-side work, not in this jar.
- **SSO end-to-end + e2e tests** — the live Casdoor OIDC (PKCE) → opaque `bff_` session
  flow and the gateway exchange-filter path are called out in the Roadmap as not yet
  covered by end-to-end tests.
- **`BffCookieAuthenticationWebFilter` only bridges services with a LOCAL `AccountStore`** —
  it resolves a `bff_` session by calling `AccountStore` directly against the DB, so it only
  works where the service owns the accounts/bff_session tables itself (today: admin-bff).
  user-bff, mod-bff, and federation-api have the identical gap on their own
  `hasAnyRole()`/`.authenticated()` gates but don't have local DB access to those tables —
  they need a different, HTTP-based bridge that resolves the session over the network
  (mirroring the gateway's own `BffSessionAuthFilter`) instead of this class. Documented as
  an intentional, tracked follow-up in the filter's own class-level Javadoc
  (`config/BffCookieAuthenticationWebFilter.java`); not yet implemented anywhere.
- **No column carries the Casdoor UUID `sub`** — `Account` is `{id, provider, handle,
  registrationComplete, roles}` and `BffSession` has no `casdoor_sub`/subject column, so
  nothing derived from the opaque `bff_`-session model can key off the Casdoor UUID subject
  today (only the folded provider:handle id). Surfacing the UUID sub (e.g. for a gateway
  introspect response) would need a new nullable schema column + `AccountStore` plumbing +
  a version bump here, coordinated with whichever consumer needs it.
- **SpotBugs is genuinely fail-mode, and `./mvnw -o clean verify` is now GREEN — re-verified
  by running the real build** (`./mvnw -o clean verify`, 2026-08-20, against the
  `hugmesh-parent` 2.8.0 / `hugmesh-build-config` 0.5.0 this module resolves): 450 tests,
  `Failures: 0, Errors: 0`, `BugInstance size is 0`, BUILD SUCCESS. This module's historical
  "SpotBugs fail mode is a no-op" framing is **stale**: `hugmesh-parent` 2.8.0 switched the
  plugin config from the silently-ignored `failOnViolation` parameter to the real one,
  `failOnError=true`, so `spotbugs:check` really does fail the build — which is what surfaced
  **8 Medium `EI_EXPOSE_REP2`** findings here (`AccountStore` ×3,
  `BffStoredMfaFactorVerifier` ×4, `WebAuthnChallengeStore` ×1) while `clean test`/`clean
  package` kept succeeding. `hugmesh-build-config` 0.4.0/0.5.0 had already fixed most of this
  class of false positive — Spring constructor-injection findings are suppressed by CLASS-NAME
  suffix (`*Service`/`*Controller`/`*Repository`/`*Client`/`*Config`/`*Handler`/`*Filter`/
  `*Resolver`), not just layer-package name — which is why the pre-#35 count of 20 findings
  (`account/`, `casdoor/`, `mfa/`, `username/`) was already down to 8: PR #35 fixed the two
  genuine `Account.roles` findings, and the exclude filter's suffix list quietly covers
  everything else in `casdoor/`/`username/`/most of `mfa/`. The last 8 were the same kind of
  Spring-injection false positive, just on classes named `*Store`/`*Verifier` — a suffix the
  shared filter deliberately does **not** cover (its maintainer note is explicit that
  app-specific bean suffixes "stay reported and get triaged on their merits rather than
  silently muted"). That triage now lives in **`spotbugs/exclude-filter.xml`**: the three
  classes by name, `EI_EXPOSE_REP2` only, carrying build-config's own guard so a genuinely
  mutable field (`byte[]`/`char[]` key material, `List`/`Map`/`Set`/`Collection`/`Date`) is
  still REPORTED inside them. It is wired through the plugin's `<excludeFilterFiles>` list,
  **not** `<excludeFilterFile>` — the latter is what the parent points at the shared baseline,
  so redeclaring it would have replaced that baseline instead of layering on it. Renaming
  `AccountStore` / `WebAuthnChallengeStore` was rejected: both are public API consumed by
  user-bff and admin-bff.

## Roadmap
This jar advances in lockstep with the platform auth roadmap; the next increments are:
- **Adopt the jar across BFFs**: with the extraction landed, complete admin-bff + user-bff
  adoption so login/session logic is fully relocated admin-bff → user-bff against this one
  shared implementation.
- **SSO end-to-end + e2e**: support the live Casdoor OIDC (PKCE) → opaque `bff_` session
  flow and the gateway exchange-filter path, with end-to-end tests.
- **MFA BFF wiring** *(substrate done)*: the shared MFA store/verifier infrastructure
  (TOTP, WebAuthn, recovery codes, `FactorType`/`CeremonyType` enums, DB-generated PKs) is
  fully landed in this library (PRs #4, #6). What remains is BFF-side wiring: per-role MFA
  defaults, step-up enforcement in admin-bff, and the Casdoor MFA bridge for the opaque
  `bff_`-session flow.
- Track the wider platform roadmap where it touches account/session/MFA: multi-tenancy
  superadmin, device-license registry, desktop app governance (SSO sudo), and OWASP
  pen-test + nuclei in CI.

_Grounded in the HugMesh current-state brief and the repo's landed code at
auth-core 2.4.2 (2026-08-05, through the MFA ceremony-test / precondition-boot-guard /
32-byte-challenge PRs #39/#40/#41), re-verified against a real `./mvnw -o -s settings.xml test`
run on 2026-08-05 (450 tests, 0 failures). Features beyond the brief and the actual code are
intentionally not invented here._
