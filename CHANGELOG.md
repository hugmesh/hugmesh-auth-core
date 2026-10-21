# Changelog — hugmesh-auth-core

Coordinates: `net.hugmesh:hugmesh-auth-core`. One `main` branch, no git tags (the org's
repos carry none — consumers pin a **version**, and the cold-build bootstrap pins the
**commit SHA** whose `pom.xml` declares that version; see `RELEASING.md`).

The **newest heading here must equal `pom.xml`'s `<version>`** and the `**Version X.Y.Z**`
line in `README.md` — pinned by `ReleaseMetadataGuardTest`, because the two have drifted
before (2.5.1 landed in `pom.xml` at `fe2bf3a` and in the README only at `dba8a82`).

---

## 2.6.0 — PREPARED, NOT PUBLISHED (prepared 2026-10-21, hugmesh-auth-core#21)

A minor bump because the change below is consumer-visible (new public API), per
`RELEASING.md` §1. Release content is the `main` commit that merges hugmesh-auth-core#21.
Like 2.5.1, it has not been published: nothing in `RELEASING.md` §3 changed.

### Added
- **Shared HTTP `bff_` session bridge** in `config/`, for services that have no local
  `AccountStore` (they cannot reach the accounts / `bff_session` tables):
  `BffSessionIntrospectionWebFilter` (the `WebFilter`), `BffSessionIntrospector` (the lookup
  interface), `HttpBffSessionIntrospector` (calls admin-bff's
  `GET /bff/internal/session/introspect` with the token as `Authorization: Bearer`) and
  `BffSessionIntrospection` (the response record). Only an explicit ASCII `active` status
  gets authorities; `suspended`/`banned` and any unrecognized status get `403` with an
  `X-Bff-Denied` reason; an introspection error, a timeout or a duplicate key in the
  response body gets `503`. It is not a `@Component`: a consumer declares it as a `@Bean`.
- **Shared authority mapping**: `BffCookieAuthenticationWebFilter.buildAuthorities` gains a
  package-private overload taking `(registrationComplete, roles, mfaSatisfied)`, which both
  the local-store filter and the HTTP bridge call, so the two can never grant different
  roles for the same session. The existing `(Account, boolean)` form delegates to it.

### Not changed
- **No consumer uses the HTTP bridge yet.** user-bff-api, mod-bff-api and federation-api
  still have to adopt it, and admin-bff's five `/bff/register|me|provision` routes are
  untouched. hugmesh-auth-core#3 stays open for that cross-repo work.
- The local-store `BffCookieAuthenticationWebFilter` behaves exactly as in 2.5.1: same
  authorities for the same account. Nothing was removed or renamed, so `2.5.1 → 2.6.0` is
  source- and binary-compatible. No consumer pin moves in this change.

---

## 2.5.1 — PREPARED, NOT PUBLISHED (prepared 2026-09-16)

Release content is `main` @ `dbdcee7` (`Merge pull request #17`). "Not published" is
measured, not assumed: the GitHub `Release` workflow has **zero runs**
(`gh run list --repo hugmesh/hugmesh-auth-core` → empty), and the GitLab registry that
`hugmesh-parent`'s `distributionManagement` names does not resolve from a developer box
(`gitlab.hugmesh.net` → NXDOMAIN). What still stands between this file and a published jar
is written out in `RELEASING.md` §3.

Operator decision (hugmesh-generator#347 line 15, 2026-09-16): *"Publish 2.5.1, keep #2
open."* Publishing the library does **not** wire MFA into any service — hugmesh-auth-core#2
stays open.

### Fixed
- **The username gate's credential could never authenticate** (`8b3043f`).
  `FederationUsernameClient` presented only a shared `X-Internal-Token` header, but
  hugmesh-federation-api authenticates `/api/federation/username/**` **exclusively** as an
  OAuth2 resource server (`SecurityConfig.java:182` `hasAnyRole("SERVICE","ADMIN","SUPERADMIN")`
  + `:289-295` `oauth2ResourceServer → o.jwt(...)`) and has no `X-Internal-Token` filter at
  all. An enabled gate therefore 401'd on every check and failed **closed** — i.e. no
  provider-derived username could be minted. Now:
  - new `casdoor/CasdoorServiceTokenClient` — a cached OAuth2 **client-credentials** mint
    against Casdoor's `POST /api/login/oauth/access_token`;
  - `FederationUsernameClient` gains a 5-arg constructor taking
    `Supplier<Mono<String>>` (a current ROLE_SERVICE bearer per call). **The 4-arg
    constructor is retained**, so this is source- and binary-compatible;
  - `FederationUsernameConfig` wires the supplier from
    `federation.username-gate.service-bearer.{casdoor-base-url,client-id,client-secret}`,
    each defaulting to the platform-wide `app.casdoor.platform.{base-url,client-id,client-secret}`
    that every other internal ROLE_SERVICE caller in the org already carries;
  - the gate's `WebClient` now goes through the jar's existing **gated** outbound-mTLS
    connector (`hugmesh.mtls.client.*` → `OidcExchangeClientSsl`, default OFF), which the
    in-cluster federation-api requires (`SSL_CLIENT_AUTH=need`);
  - a boot **WARN** names exactly which of the three credentials is missing when the gate is
    enabled without them;
  - fail-closed widened from transport/parse to also cover mint, non-2xx status and
    empty-body responses.
  The legacy header is still stamped when configured, for wire compatibility.
  **This is jar-side only** — the gate stays OFF in-cluster and four consumer-side things
  still gate it: hugmesh-generator#376.
- **`AccountStore` folded handles with the default locale** (`fe2bf3a`). Ten call sites used
  `String.toLowerCase()` with no `Locale`. Under a Turkish default locale (`tr`/`az`)
  `'I'` folds to `'ı'`, not `'i'`, so an invited `ALICE@example.com` could miss its
  allowlist row, `grant`/`revoke` could miss their namespace rows, and the `adminEmails`
  split could drop an admin. All ten now use `Locale.ROOT`, matching the write-side fold
  `idFor` already used since 2.3.4.
  *Not closed by this release:* **ten** bare, default-locale folds remain outside
  `AccountStore` (`grep -rn -aE '\.to(Lower|Upper)Case\(\)' src/main/java` on `dbdcee7`) —
  `ReservedNames:165,184`, `CasdoorAdminClient:125,465,528`,
  `BffCookieAuthenticationWebFilter:190`, `MfaFactorVerifier:42`,
  `InternalSurfaceBootGuard:42`, `TotpService:176`, `RecoveryCodeService:103`. Tracked as
  hugmesh-auth-core#15, which records that `ReservedNames.isReserved` is the one that fails
  **OPEN**. Deliberately out of this release's scope.

### Documentation
- `BffSession`: the open "no column carries the Casdoor UUID `sub`" TODO is **answered and
  closed** (`ff4a20b`) — the consumer that needed it (the gateway's route-access pin match)
  is served by admin-bff's own `account.casdoor_sub` (Liquibase `292-account-casdoor-sub`)
  surfaced through `/bff/internal/session/introspect`. Deliberately **not** carried on this
  record: it belongs to the account, not the session, and a field here would force a
  version-bump chain through every consumer for a column exactly one of them uses.
- README: the MFA step-up path is described as wired-and-dark rather than "not yet complete"
  (`b04d0cb`), with `file:line` pointers.

### Release plumbing — added 2026-09-17, no code change to the artifact
Operator decision 27 (hugmesh-generator#347): *"B for the mechanism, A prepared"*. The
source-build mechanism is untouched — `hugmesh-generator/tests/stack/m2-bootstrap.sh` still
builds this library from a pinned SHA, and with no `-s` the effective repository list of this
project is still `central` alone. What changed is that the **publish path is now real and
unfired**:
- `.github/maven-ci-settings.xml` — CI-only Maven settings declaring the three upstream
  GitHub Packages repositories as both `<repositories>` and `<pluginRepositories>`, plus the
  `github` deploy server. Deliberately NOT in `pom.xml`: `maven.pkg.github.com` answers 401
  to an unauthenticated GET, so a pom entry would break every developer build and every cold
  compose build. `RELEASING.md` §3.2.
- `.github/workflows/release.yml` — both maven steps now pass `-s .github/maven-ci-settings.xml`.
- `.github/workflows/release-chain.yml` — one `workflow_dispatch` that publishes all four
  links in build order (`build-config` → `parent` → `commons` → `auth-core`), gated on a
  literal `PUBLISH` confirmation and on a `RELEASE_CHAIN_TOKEN` secret that does not exist
  yet. `RELEASING.md` §6.2 is the operator's click list.
- `ReleaseMetadataGuardTest` grew from 4 checks to 12, all mutation-tested: production was
  broken eight ways (flag dropped, packages URL moved into the pom, `<pluginRepositories>`
  deleted, deploy `<server>` deleted, chain reordered, a tag trigger added, the settings file
  deleted, the chain rewired to `GITHUB_TOKEN`) and the guard went red on all eight.

**Corrected 2026-09-18, after adversarial review — two defects in the above.**
- **The prepared chain could not have read its own upstreams.** Every upstream `<server>` in
  the CI settings file authenticated with `${env.GITHUB_TOKEN}`, but `secrets.GITHUB_TOKEN`
  is scoped to the repository whose workflow is running; GitHub does not extend it across
  repositories for package reads. The first real run would have died on
  `Could not resolve net.hugmesh:hugmesh-parent:pom:2.8.0` — *the same string these very
  docs teach a reader to interpret as "the upstream is not published yet"*, so it was set up
  to be misdiagnosed into a pointless re-publish. Fixed three ways: the upstream servers now
  read `${env.UPSTREAM_PACKAGES_*}`, injected as
  `${{ secrets.PACKAGES_READ_TOKEN || secrets.GITHUB_TOKEN }}` so an operator can override;
  `release.yml` gained a preflight step that probes each upstream registry with that exact
  credential and reports `401`/`403` as an authorisation failure rather than as absence; and
  `RELEASING.md` §6.1 blocker 4 / §6.2 step 2 record the two grant routes and that **going
  public does not perform either of them**.
- **The guard blocked ordinary pre-merge CI.** `everyWorkflowIsDispatchOnly` required *every*
  file under `.github/workflows` to be `workflow_dispatch`-only, so a plain `ci.yml` running
  `./mvnw test` on `pull_request` failed the build with *"Every workflow in this repo
  publishes or can publish an immutable coordinate"* — false of a test-only workflow, and
  this repo has no pre-merge CI yet. Replaced by `everyPublishingWorkflowIsDispatchOnly`,
  which classifies a workflow as publishing on any of: a `deploy` in a parsed `run:`, a
  `gh workflow run` dispatch, a `permissions:` block mentioning `packages`, or the raw text
  naming `maven.pkg.github.com`. Exemption is deliberately hard to obtain, and the test also
  asserts that `release.yml` and `release-chain.yml` are never exempted, so it cannot pass
  vacuously.

**Still not published, and it cannot be published today.** No Actions job in this org starts
at all while the repos are private: the annotation on the most recent runs is *"The job was
not started because recent account payments have failed or your spending limit needs to be
increased."* `RELEASING.md` §6.1.

### Not in this release
No schema change, no dependency change, no removal. `pom.xml`'s dependency set is
byte-identical to 2.5.0's.

---

## 2.5.0 — 2026-09-02 (`main` @ `1578565`)

### Added
- **Domain-scoped registration gate** (auth-core#1, PR #8): `AllowlistRepository` gains
  `existsByProviderAndHandleAndDomain` / `deleteByProviderAndHandleAndDomain` and a
  domain-aware `insertIfAbsent`; `AccountStore` gains `isEmailInvited(email, domain)` and
  `isDiscordInvited(handle, domain)`. This closed a cross-brand hole where a brand-X invite
  satisfied a brand-Y registration.
- The unscoped 1-arg overloads remain on the API surface, `@Deprecated` but callable —
  deleting them is a breaking change that needs the whole consumer chain to re-pin first.

### Build
- `spotbugs/exclude-filter.xml` triages the eight `EI_EXPOSE_REP2` findings on the
  `*Store`/`*Verifier` beans so `mvn verify` passes with SpotBugs in genuine fail mode.
  Declared via `<excludeFilterFiles>` (plural) so it **layers on** the shared
  `hugmesh/spotbugs-exclude.xml` baseline instead of replacing it.

---

## 2.4.2 — 2026-08-05 (pin `401ca9e`, the commit whose pom declares the `net.hugmesh` coordinate)

### Fixed
- MFA hardening (PRs #39/#40/#41): `WebAuthnService.newChallengeBase64Url` challenge
  generation, TOTP-replay, recovery-code CAS and the WebAuthn owner guard.

### Why the version exists
2.4.1 stopped being a trustworthy immutable coordinate the moment #39/#40/#41 merged: the
GitLab `deploy:maven` job re-ran `deploy` at whatever version `pom.xml` held on **every**
`main` merge, so a published 2.4.1 was overwritten in place. 2.4.2 restores a meaningful
pin. That mutability is the reason `RELEASING.md` §1 insists on a version bump in the same
PR as any consumer-visible change.

---

## Earlier

Pre-2.4.2 history is in `README.md`'s "Current State" bullets (per-version, with
`file:line` pointers) and in `git log -- pom.xml`, which shows every version bump.
