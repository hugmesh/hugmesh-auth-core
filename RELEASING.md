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

**What `ReleaseMetadataGuardTest` enforces, and why it PARSES `release.yml` rather than
grepping it.** Nine checks. The original four: the three version statements agree; the
deploy step carries `-DaltDeploymentRepository` pointed at *this* repository (§3.1); and
the workflow's trigger set is exactly `{workflow_dispatch}`. Five more arrived with the
publish-path preparation (§3.2): **every** workflow in `.github/workflows` is
`workflow_dispatch`-only, not just `release.yml`; every maven invocation in `release.yml`
passes `-s .github/maven-ci-settings.xml`; that settings file declares each upstream link
as **both** a `<repository>` and a `<pluginRepository>` and carries a `<server>` for every
id including `github`; `maven.pkg.github.com` appears in **neither** `pom.xml` **nor** the
repo-root `settings.xml`; and `release-chain.yml` dispatches all four links in build order
off `secrets.RELEASE_CHAIN_TOKEN`. Each of those five was mutation-tested — production was
broken eight different ways and the guard went red on all eight (2026-09-17). The first cut of that class string-matched the
workflow text, and two adversarial reviews found the same failure mode from opposite ends —
a guard that matches one *spelling* of a config file fails open on every other spelling of
the same meaning. Measured green against a reverted workflow: `on: [push, workflow_dispatch]`,
`on: {workflow_dispatch: {}, push: {tags: [v*]}}`, a quoted `"push":` key, and `release:` /
`schedule:` triggers all evaded the trigger check, and deleting the flag from the `run:` line
evaded the deploy check as long as it survived in the comment block above it. Both checks now
read the **parsed** document: comments do not exist after parsing, and every YAML spelling of
a trigger collapses to the same key set. The trigger check is an allowlist
(`ONLY_ALLOWED_TRIGGER`), not a blacklist of `push` spellings. **If a new trigger is ever
deliberate, widen that constant in the same change and record why here** — the whole point is
that publish-on-its-own cannot arrive as a silent edit.

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

### 3.2 Dependency resolution — FIXED, CI-only (operator decision 27, 2026-09-17)

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
workflow's "Build and test" step used to fail at parent resolution, before `deploy` was
ever reached. It builds on a developer box only because `~/.m2/repository/net/hugmesh/`
holds locally-installed copies.

**The fix: `.github/maven-ci-settings.xml`, passed with `-s` by the release workflow and by
nothing else.** Operator decision 27 (hugmesh-generator#347, 2026-09-17) is *"B for the
mechanism, A prepared"* — keep source-building (`m2-bootstrap.sh` from pinned SHAs)
as today's mechanism, and make the publish path real but unfired. A CI-only settings file
is the only shape that adds a repository for CI without adding one for everybody, because
**GitHub Packages requires authentication even to READ**. Measured 2026-09-17:

```
$ curl -s -o /dev/null -w '%{http_code}\n' \
    https://maven.pkg.github.com/hugmesh/hugmesh-parent/net/hugmesh/hugmesh-parent/2.8.0/hugmesh-parent-2.8.0.pom
401
$ curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $(gh auth token)" <same URL>
401          # classic token, scopes gist/project/read:org/repo/workflow — no read:packages
```

A `<repositories>` entry in `pom.xml` would therefore turn every unauthenticated
`./mvnw verify` and every `m2-bootstrap.sh` cold build into a 401. It is not a convenience,
it is an outage — which is exactly why it is not there, and why
`ReleaseMetadataGuardTest.packagesRepositoryStaysOutOfThePomAndTheGitlabSettings` fails the
build if the URL ever appears in `pom.xml` or the repo-root `settings.xml`.

Two details in that file that are easy to get wrong and expensive to debug:

- **`<pluginRepositories>` as well as `<repositories>`.** `net.hugmesh:hugmesh-build-config`
  is not a project dependency — `hugmesh-parent` puts it on the **plugin** classpath of
  maven-pmd-plugin / maven-checkstyle-plugin / spotbugs-maven-plugin so each analyser reads
  the curated ruleset off its own classloader. Maven resolves a plugin's `<dependencies>`
  from the **plugin** repositories. A repositories-only file resolves the parent POM and
  then dies at `verify` on the ruleset jar.
- **A `<server><id>github</id>` inside it.** `-s` *replaces* the user settings file, so the
  entry `actions/setup-java` writes into `~/.m2/settings.xml` is invisible to a build run
  with this file, and the deploy step's `-DaltDeploymentRepository=github::default::…`
  would upload with no credential at all.

Proof it is CI-only, measured on this branch 2026-09-17 (offline, so no network can
contribute):

```
$ ./mvnw -o -q -B -ntp help:evaluate -Dexpression=project.repositories -DforceStdout
    <id>central</id>                     # <- unchanged: developer builds, m2-bootstrap.sh
$ ./mvnw -o -q -B -ntp -s .github/maven-ci-settings.xml help:evaluate -Dexpression=project.repositories -DforceStdout
    <id>github-hugmesh-build-config</id>
    <id>github-hugmesh-parent</id>
    <id>github-hugmesh-commons</id>
    <id>central</id>
$ ./mvnw -o -q -B -ntp -s .github/maven-ci-settings.xml help:evaluate -Dexpression=project.pluginRepositories -DforceStdout
    <id>github-hugmesh-build-config</id>   # ...and the same three as PLUGIN repositories
    <id>github-hugmesh-parent</id>
    <id>github-hugmesh-commons</id>
    <id>central</id>
```

**What is still not proven.** No CI job has ever executed this file — see §6. The
resolution route is correct by construction and by the effective-model measurement above,
but "correct effective model" is not "the artifacts downloaded". Nothing is published yet,
so there is nothing to download.

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
file, not the pom — decided as such by the operator on 2026-09-17 and landed as
`.github/maven-ci-settings.xml` in this repo, in `hugmesh-parent` and in `hugmesh-commons`
(`hugmesh-build-config` needs none: it has no `net.hugmesh` upstream of its own, so Central
is enough for it).

**One trigger, not four.** `.github/workflows/release-chain.yml` in this repo dispatches all
four `Release` workflows in that order and waits for each, so launch day is one button
rather than four buttons in an order nobody remembers. It refuses to start unless the
`confirm` input is the literal `PUBLISH` **and** `secrets.RELEASE_CHAIN_TOKEN` is present —
`secrets.GITHUB_TOKEN` is scoped to the repository it runs in and cannot dispatch a workflow
in the other three, so a chain wired to it would fail at the first hop with a 404 that reads
like a missing workflow.

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
- [x] §3.2 resolution route agreed and landed — `.github/maven-ci-settings.xml` (2026-09-17).
- [ ] §3.2's other half — the upstream chain actually **published**. Still open; see §6.
- [ ] `Release` workflow still `workflow_dispatch`-only — `ONLY_ALLOWED_TRIGGER` unwidened.
- [ ] `Release` workflow run from the GitHub UI (`workflow_dispatch`; it never runs on push).
- [ ] The published coordinate actually fetched back once, by a consumer, before any pin moves.
- [ ] `m2-bootstrap.sh` `PINS` row added and `test-m2-bootstrap.sh` run.
- [ ] Consumer pins bumped (§4), each with its manifest env in the same change.

---

## 6. Launch day — can this publish now, and what does the operator click?

Operator decision 27's note asks for the packages to be **published on GitHub under
hugmesh at launch**, and: *"If we can publish the packages now before unpriviting and going
public, let's do that."*

### 6.1 Can it publish now, while the repos are private? Measured: NO — two independent blockers

**Blocker 1 — no Actions job in this org starts at all today.** Not "fails"; *never starts*.
Measured 2026-09-17 on the most recent runs across the org:

```
$ gh api /repos/hugmesh/hugmesh-generator/actions/runs/35288155335/jobs --jq '.jobs[] | {name,conclusion,steps}'
{"name":"shell suites (alpine)","conclusion":"failure","steps":[]}     # zero steps, 2s wall
$ gh api /repos/hugmesh/hugmesh-generator/check-runs/105424969429/annotations --jq '.[0].message'
The job was not started because recent account payments have failed or your spending limit
needs to be increased. Please check the 'Billing & plans' section in your settings
```

Private-repository Actions minutes are billed; public-repository minutes on standard runners
are free. So this blocker **dissolves by itself the moment the repos go public** — it is the
strongest single argument for "prepare now, fire on the day", and it is why nothing here was
run rather than merely not yet run.

**Blocker 2 — no credential on this box can publish either.** The manual fallback (`mvn
deploy` from a developer machine) needs `write:packages`. The keyring token carries
`gist, project, read:org, repo, workflow` — no `write:packages`, and no `read:packages`
either, which is why even *confirming* what is or is not already published is impossible
here (`gh api /orgs/hugmesh/packages?package_type=maven` → HTTP 403 *"You need at least
read:packages scope to list packages"*, and `maven.pkg.github.com` answers 401 to that token
exactly as it does to an anonymous request).

**A third reason not to force it, even if a token appeared.** A package published from a
private repository is private, and GitHub Packages scopes a Maven package's visibility to
its repository. Publishing early would produce four private coordinates that nobody outside
the org can resolve, and the operator's goal is packages the public can consume. Publishing
on the day the repos go public gets that for free.

### 6.2 The click list for the day the repos go public

1. **Make the four repos public**: `hugmesh-build-config`, `hugmesh-parent`,
   `hugmesh-commons`, `hugmesh-auth-core`. Blocker 1 dies here.
2. **Create the cross-repo credential.** A PAT with **Actions: read and write** on those
   four repos (fine-grained), or a classic token with `repo` + `workflow`. Store it as
   **`RELEASE_CHAIN_TOKEN`** — an organisation secret visible to the four repos, or a repo
   secret on `hugmesh-auth-core` alone. This is the *only* operator-held secret in the whole
   path: each repo's own deploy step uses the automatic `secrets.GITHUB_TOKEN`.
3. **Run one workflow.** `hugmesh-auth-core` → Actions → **Release chain** → Run workflow,
   `confirm` = `PUBLISH`. It dispatches, in order, `hugmesh-build-config` →
   `hugmesh-parent` → `hugmesh-commons` → `hugmesh-auth-core`, waiting for each and stopping
   at the first failure rather than publishing the rest on top of a hole.
   (Skipping step 2 and clicking each repo's own **Release** workflow by hand, in that order,
   is the same publish with four buttons instead of one.)
4. **Fetch one coordinate back** from a clean local repository before any consumer pin moves
   — §5. A publish that reports success and a coordinate that resolves are not the same
   claim.
5. **Add the `2.5.1` row** to `hugmesh-generator/tests/stack/m2-bootstrap.sh`'s `PINS` table
   and run `tests/stack/test-m2-bootstrap.sh` (§3.4).

### 6.3 What nobody has verified, and cannot verify from here

- **No CI job has ever executed `.github/maven-ci-settings.xml`.** Its effective model is
  measured (§3.2) and its shape is guarded, but the first real run is the first real run.
- **Whether anything is already published is unknown, not "nothing".** It is inferred from
  zero workflow runs plus a dead GitLab host. Confirming it needs `read:packages`.
  A `maven-metadata-github.xml` dated 2026-09-16 17:35 PDT sits in this box's
  `~/.m2/repository/net/hugmesh/hugmesh-auth-core/` — that is a *local* staging artefact the
  deploy plugin writes while merging metadata, so it evidences a deploy **attempt** from a
  developer machine, not a successful upload. The sibling `_remote.repositories` files all
  record locally-installed origins.
- **`hugmesh-parent`'s runner JDK.** It pinned `java-version: '21'` while the metapom's
  `java.version` is 25; aligned to 25 on this round, still never executed.

---

## 7. What decision 27 deliberately did NOT change

`hugmesh-generator/tests/stack/m2-bootstrap.sh` still builds these four libraries **from
pinned commit SHAs**, and that remains the mechanism for the compose/local lane. Nothing in
this round points any lane at a registry. The measurement that proves it: with no `-s`, the
effective repository list of this project is still `central` alone (§3.2). If a future change
makes the compose lane resolve from GitHub Packages, it needs its own decision — the one
taken here was explicitly *"keep source-building, prepare the publish path"*.
