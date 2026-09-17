# Releasing hugmesh-auth-core

Written 2026-09-16 while preparing **2.5.1** (operator decision, hugmesh-generator#347
line 15: *"Publish 2.5.1, keep #2 open."*). Everything below is measured on this box, with
the command that measured it, because the release path in this repo has three separate
ways of looking finished while publishing nothing.

---

## 1. What a release IS here

There are **no git tags** in any of the org's Java repos. A "release" is exactly two things:

1. `pom.xml`'s `<version>` is bumped **in the same PR as the change**, and
2. a jar for that coordinate is deployed to a Maven registry the consumers resolve from.

A consumer pins the **version** (`hugmesh-admin-bff-api/pom.xml:143` → `2.5.0`,
`hugmesh-user-bff-api/pom.xml:98` → `2.4.2`). The cold-build bootstrap
(`hugmesh-generator/tests/stack/m2-bootstrap.sh`, the `PINS` table) additionally pins the
**commit SHA** whose `pom.xml` declares that version, because it builds these libraries from
source instead of resolving them.

**Bump the version in the same PR as any consumer-visible change.** The GitLab
`deploy:maven` job re-runs `deploy` on *every* default-branch commit at whatever version the
pom holds, so leaving the pom on an already-published version silently overwrites that
coordinate in place. That is exactly why 2.4.2 exists (it re-pinned after 2.4.1 was
published mutable) and why `CHANGELOG.md` and `ReleaseMetadataGuardTest` exist.

Keep the three version statements in lockstep — `pom.xml`, the `**Version X.Y.Z**` line in
`README.md`, and the newest heading in `CHANGELOG.md`. They have drifted before (2.5.1
landed in the pom at `fe2bf3a` and in the README only at `dba8a82`);
`ReleaseMetadataGuardTest` now fails the build on that drift.

## 2. The two publish paths this repo carries

| path | file | target | state measured 2026-09-16 |
|---|---|---|---|
| GitLab CI | `.gitlab-ci.yml` `deploy:maven` | `${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/maven` on `gitlab.hugmesh.net` | **cannot run.** No repo has a GitLab remote (`git remote -v` → two GitHub URLs), and `gitlab.hugmesh.net` does not resolve (`getent hosts` → no answer; `curl` → "Could not resolve host"). That host is deployed *by the mesh itself* (`hugmesh-generator/specs/cluster/apps/03-gitlab.yaml`), so it exists only where a mesh is running. |
| GitHub Actions | `.github/workflows/release.yml` | GitHub Packages, `maven.pkg.github.com/hugmesh/hugmesh-auth-core` | **has never run** (`gh run list --repo hugmesh/hugmesh-auth-core` → empty) and, before this branch, deployed to the GitLab id (see §3.1). |

`settings.xml` in the repo root serves the **GitLab** path only (it injects
`CI_JOB_TOKEN` as a `Job-Token` header). It is not used by the GitHub workflow, which lets
`actions/setup-java` generate the `<server>` entry instead.

## 3. What still blocks an actual 2.5.1 publish

### 3.1 Deploy target — FIXED on this branch

`pom.xml` declares no `distributionManagement`; it inherits the parent's. Measured:

```
$ ./mvnw -q -B -ntp help:evaluate -Dexpression=project.distributionManagement.repository.id -DforceStdout
gitlab-maven
$ ./mvnw -q -B -ntp help:evaluate -Dexpression=project.distributionManagement.repository.url -DforceStdout
${env.CI_API_V4_URL}/projects/${env.CI_PROJECT_ID}/packages/maven
```

The `${env.*}` placeholders are **not interpolated** — those variables do not exist outside
GitLab CI, so the literal `${env...}` string is the URL. So the old deploy step
(`./mvnw -B -ntp deploy -DskipTests`, with `actions/setup-java` having provisioned
credentials for server id `github`) aimed a `gitlab-maven` server id at an uninterpolated
URL: wrong registry, wrong credential id.

The fix on this branch is the pattern the two sibling library repos already commit —
`hugmesh-parent/.github/workflows/release.yml:24` and
`hugmesh-build-config/.github/workflows/release.yml:37`:

```
./mvnw -B -ntp deploy -DskipTests -DaltDeploymentRepository=github::default::https://maven.pkg.github.com/${{ github.repository }}
```

`altDeploymentRepository` overrides the inherited `distributionManagement` entirely, and its
`github` id matches the server `setup-java` provisions from `secrets.GITHUB_TOKEN` (which is
**automatic** — no operator-held secret is involved in this step).

### 3.2 Dependency resolution — STILL BLOCKED, and it blocks the whole chain

`./mvnw verify` on a clean runner cannot resolve this project's own parent. Measured:

```
$ ./mvnw -q -B -ntp help:evaluate -Dexpression=project.repositories -DforceStdout | grep -E '<id>|<url>'
    <id>central</id>
    <url>https://repo.maven.apache.org/maven2</url>
```

Central is the **only** repository in the effective model — no `<repositories>` block exists
in this pom or in `hugmesh-parent`'s — and none of the three `net.hugmesh` artifacts this
build needs are on Central:

```
$ curl -o /dev/null -w '%{http_code}\n' https://repo1.maven.org/maven2/net/hugmesh/hugmesh-parent/2.8.0/hugmesh-parent-2.8.0.pom        # 404
$ curl -o /dev/null -w '%{http_code}\n' https://repo1.maven.org/maven2/net/hugmesh/hugmesh-commons/2.1.0/hugmesh-commons-2.1.0.pom      # 404
$ curl -o /dev/null -w '%{http_code}\n' https://repo1.maven.org/maven2/net/hugmesh/hugmesh-build-config/0.5.0/hugmesh-build-config-0.5.0.pom  # 404
```

`actions/setup-java`'s `server-id` input writes a `<server>` (credentials) into the
generated `settings.xml`; it does **not** declare a repository to fetch from. So the
workflow's "Build and test" step fails at parent resolution, before `deploy` is ever
reached. It builds on a developer box only because `~/.m2/repository/net/hugmesh/` holds
locally-installed copies.

Nothing has been published to GitHub Packages either — `hugmesh-parent`,
`hugmesh-build-config` and `hugmesh-commons` all report **zero** workflow runs
(`gh run list --repo hugmesh/<repo>`), and `hugmesh-commons` has no `.github/workflows`
directory at all (`gh api repos/hugmesh/hugmesh-commons/contents/.github/workflows` → 404).
Listing the org's packages to confirm needs a token with `read:packages`, which this box's
token does not carry (`gh api /orgs/hugmesh/packages?package_type=maven` → HTTP 403
"You need at least read:packages scope"), so **"nothing is published" is inferred from zero
runs, not read off the registry**.

### 3.3 The order a first GitHub Packages publish has to go in

`hugmesh-build-config:0.5.0` → `hugmesh-parent:2.8.0` → `hugmesh-commons:2.1.0` (jar **and**
`tests` classifier — this repo's test scope compiles against it) → `hugmesh-auth-core:2.5.1`.
`build-config` is first because it is the parent's PMD/SpotBugs ruleset dependency, and it is
the only one of the four with no `<parent>` of its own. Each link also needs a resolution
route for the ones before it (§3.2) — GitHub Packages requires authentication even to
*read*, so declaring `maven.pkg.github.com` in the poms would break every unauthenticated
local build and the `m2-bootstrap.sh` cold build. The right place is a CI-only settings
file, not the pom. **That is a design call nobody has made, so nothing inert was landed for
it here.**

### 3.4 What a release does NOT do

Publishing the jar does not wire MFA into any service and does not change any running mesh:

- The **compose/local** lane never resolves from a registry — `m2-bootstrap.sh` builds these
  libraries from pinned SHAs. A published 2.5.1 reaches it only when its `PINS` table gains a
  `hugmesh-auth-core|<sha>|hugmesh-auth-core|2.5.1|jar|net/hugmesh` row. That table has
  drifted four times already (2.4.0 → 2.4.1 → 2.4.2 → 2.5.0), each time surfacing as
  *"Could not find artifact net.hugmesh:hugmesh-auth-core:jar:<new> in gitlab-maven"* during a
  cold build. Run `hugmesh-generator/tests/stack/test-m2-bootstrap.sh` after every release.
- No consumer moves until **its own** pom is bumped: see §4.
- hugmesh-auth-core#2 stays **open** — the operator said so explicitly.

## 4. Consumer chain after 2.5.1 publishes

| consumer | pins today | needs | then needs, in its manifest |
|---|---|---|---|
| `hugmesh-admin-bff-api` | **2.5.0** (`pom.xml:143`) | bump to 2.5.1 | `APP_CASDOOR_PLATFORM_BASE_URL` / `_CLIENT_ID` / `_CLIENT_SECRET`, plus `HUGMESH_MTLS_CLIENT_ENABLED=true` and the client stores, before `FEDERATION_USERNAME_GATE_ENABLED` can ever be true — hugmesh-generator#376 boxes 2–5 |
| `hugmesh-user-bff-api` | **2.4.2** (`pom.xml:98`) | bump to 2.5.1 (2.5.0's domain-scoped overloads come with it) | nothing new for the username gate; it does not call it |
| `hugmesh-gateway` | does **not** depend on this jar | — | — (it depends on `hugmesh-commons`, deliberately: no r2dbc/casdoor/mfa on the gateway classpath) |
| `hugmesh-generator` | `m2-bootstrap.sh` `PINS` | a `2.5.1` row at the release SHA | — |

`2.4.2 → 2.5.1` and `2.5.0 → 2.5.1` are both source- and binary-compatible: the deprecated
1-arg allowlist overloads are still present, and `FederationUsernameClient` kept its 4-arg
constructor alongside the new 5-arg one.

## 5. The checklist

- [ ] Version bumped in `pom.xml`, `README.md` (`**Version X.Y.Z**`) and `CHANGELOG.md` —
      `./mvnw -o test -Dtest=ReleaseMetadataGuardTest` proves the three agree.
- [ ] `CHANGELOG.md`'s newest section names what changed **and** what did not.
- [ ] `./mvnw -B -ntp verify` green **with Docker available** (the MFA repo slices run on real
      Postgres via Testcontainers; without Docker they are the only thing that drops out).
- [ ] §3.2 resolved — the upstream chain published and a CI-only resolution route agreed.
- [ ] `Release` workflow run from the GitHub UI (`workflow_dispatch`; it never runs on push).
- [ ] The published coordinate actually fetched back once, by a consumer, before any pin moves.
- [ ] `m2-bootstrap.sh` `PINS` row added and `test-m2-bootstrap.sh` run.
- [ ] Consumer pins bumped (§4), each with its manifest env in the same change.
