#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# test-release-channel.sh: tests for the release channels of .github/workflows/release.yml
# in a net.hugmesh Maven library. The same file is in hugmesh-build-config, hugmesh-parent,
# hugmesh-commons and hugmesh-auth-core; keep the four copies equal.
#
#   1. scripts/release-channel.sh against throwaway git repositories with an origin:
#      beta from main, stable from release/X.Y, Latest only on the newest line, and every
#      refusal (wrong branch, older patch, -rc, mismatched tag, missing branch).
#   2. the workflow's own "Version guard" step (id: guard), run from release.yml itself
#      against a throwaway pom.xml: main and release/X.Y verify, a v<version> tag releases,
#      everything else is refused and sets no kind.
#   3. the workflow's own `gh release create` step, run with a stub gh: a beta is a
#      prerelease and never Latest; a stable is Latest only when the channel script says so.
#   4. wiring: the release/** trigger, the stable-channel marker the org release script
#      looks for, fetch-depth: 0, the deploy gated on kind == 'release', the Latest answer
#      taken right before `gh release create`.
#
# The versions in the fixtures are derived from this repo's pom.xml, so a version bump
# needs no edit here.
#
# Run: bash scripts/test-release-channel.sh   (needs bash, git and python3; no network)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd -- "${here}/.." && pwd)"
script="${here}/release-channel.sh"
workflow="${root}/.github/workflows/release.yml"

pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }

work="$(mktemp -d "${TMPDIR:-/tmp}/test-release-channel.XXXXXX")"
trap 'rm -rf "${work}"' EXIT

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
# Keep git away from the runner's own config: a self-hosted runner shares its host's home.
export GIT_CONFIG_NOSYSTEM=1 HOME="${work}/home" XDG_CONFIG_HOME="${work}/xdg" GIT_CONFIG_GLOBAL="${work}/gitconfig"
mkdir -p "${HOME}"
git config --global init.defaultBranch main
git config --global commit.gpgsign false
git config --global tag.gpgsign false

# ── fixture versions, from pom.xml ───────────────────────────────────────────
pom_version="$(python3 -I -c 'import sys, xml.etree.ElementTree as E
v = E.parse(sys.argv[1]).getroot().find("{http://maven.apache.org/POM/4.0.0}version")
print(v.text.strip() if v is not None and v.text else "")' "${root}/pom.xml")"
core="${pom_version%%-*}"
if ! [[ "${core}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "FAIL pom.xml version '${pom_version}' is not MAJOR.MINOR.PATCH[-...]"
  exit 1
fi
X="${BASH_REMATCH[1]}"
Y="${BASH_REMATCH[2]}"
Z="${BASH_REMATCH[3]}"
XY="${X}.${Y}"                  # this repo's line
NXY="${X}.$((Y + 1))"           # a newer line
S0="${XY}.${Z}"                 # a stable on this line
S1="${XY}.$((Z + 1))"           # the next patch on this line
B1="${S0}-beta.1"               # a beta of it
echo "fixtures from pom.xml ${pom_version}: line ${XY}, stable ${S0}, next patch ${S1}, beta ${B1}, newer line ${NXY}"

# ── 1. release-channel.sh ────────────────────────────────────────────────────
# origin: main has the beta commit; release/XY has S0 and S1 commits; release/NXY has NXY.0.
origin="${work}/origin.git"
src="${work}/src"
git init -q "${src}"
commit() { git -C "${src}" commit -q --allow-empty -m "$1"; git -C "${src}" rev-parse HEAD; }
base="$(commit base)"
git -C "${src}" checkout -q -b "release/${XY}"
c_s0="$(commit "stable ${S0}")"
c_s1="$(commit "stable ${S1}")"
git -C "${src}" checkout -q -b "release/${NXY}" "${base}"
c_n0="$(commit "stable ${NXY}.0")"
git -C "${src}" checkout -q main
c_b1="$(commit "beta ${B1}")"
git clone -q --bare "${src}" "${origin}"

# clone <name> <tag:commit>...: a checkout of origin with those tags, like fetch-depth: 0
clone() {
  local d spec
  d="${work}/$1"
  shift
  rm -rf "${d}"
  git clone -q "${origin}" "${d}"
  for spec in "$@"; do
    git -C "${d}" tag "${spec%%:*}" "${spec#*:}"
  done
  printf '%s' "${d}"
}

# run_channel <dir> <ref> <version> <sha>: sets rc and out
run_channel() {
  rc=0
  out="$(cd "$1" && GITHUB_REF="$2" VERSION="$3" GITHUB_SHA="$4" GITHUB_OUTPUT="" RELEASE_GIT_DIR="$1" bash "${script}" 2>&1)" || rc=$?
}
expect_channel() { # name dir ref version sha channel latest
  run_channel "$2" "$3" "$4" "$5"
  if [ "${rc}" -eq 0 ] && grep -qx "channel=$6" <<< "${out}" && grep -qx "latest=$7" <<< "${out}"; then
    ok "channel: $1"
  else
    bad "channel: $1 (rc=${rc}, wanted channel=$6 latest=$7): ${out}"
  fi
}
expect_refused() { # name dir ref version sha
  run_channel "$2" "$3" "$4" "$5"
  if [ "${rc}" -ne 0 ] && ! grep -q '^channel=' <<< "${out}"; then
    ok "channel refuses: $1"
  else
    bad "channel refuses: $1 (rc=${rc}): ${out}"
  fi
}

d="$(clone plain)"
expect_channel "main verifies" "${d}" refs/heads/main "${B1}" "${c_b1}" none false
expect_channel "release/${XY} verifies" "${d}" "refs/heads/release/${XY}" "${S0}" "${c_s0}" none false
expect_refused "release/${XY} with a ${NXY} pom" "${d}" "refs/heads/release/${XY}" "${NXY}.0" "${c_s0}"
expect_refused "release/${XY}-hotfix (not release/X.Y)" "${d}" "refs/heads/release/${XY}-hotfix" "${S0}" "${c_s0}"
expect_refused "release/foo" "${d}" refs/heads/release/foo "${S0}" "${c_s0}"
expect_refused "a feature branch" "${d}" refs/heads/feature/x "${B1}" "${c_b1}"
expect_refused "a pull request ref" "${d}" refs/pull/7/merge "${B1}" "${c_b1}"

d="$(clone beta "v${B1}:${c_b1}")"
expect_channel "beta tag on main" "${d}" "refs/tags/v${B1}" "${B1}" "${c_b1}" beta false
d="$(clone beta-off-main "v${B1}:${c_s0}")"
expect_refused "beta tag on a release branch commit" "${d}" "refs/tags/v${B1}" "${B1}" "${c_s0}"
expect_refused "tag that is not v+pom version (beta tag on main, stable pom)" "${d}" "refs/tags/v${B1}" "${S0}" "${c_b1}"
# An -rc tag is refused for having no channel, wherever its commit is.
expect_refused "-rc tag on main" "${d}" "refs/tags/v${S0}-rc.1" "${S0}-rc.1" "${c_b1}"
expect_refused "-rc tag on release/${XY}" "${d}" "refs/tags/v${S0}-rc.1" "${S0}-rc.1" "${c_s0}"
expect_refused "beta.0" "${d}" "refs/tags/v${S0}-beta.0" "${S0}-beta.0" "${c_b1}"
expect_refused "unknown commit" "${d}" "refs/tags/v${B1}" "${B1}" 0123456789abcdef0123456789abcdef01234567

d="$(clone stable-first "v${S0}:${c_s0}")"
expect_channel "first stable on release/${XY} is Latest" "${d}" "refs/tags/v${S0}" "${S0}" "${c_s0}" stable true
expect_refused "stable tag on a main commit" "${d}" "refs/tags/v${S0}" "${S0}" "${c_b1}"
expect_refused "stable tag on another line's branch" "${d}" "refs/tags/v${S0}" "${S0}" "${c_n0}"

d="$(clone stable-patch "v${S0}:${c_s0}" "v${S1}:${c_s1}")"
expect_channel "patch on the newest line is Latest" "${d}" "refs/tags/v${S1}" "${S1}" "${c_s1}" stable true
expect_refused "an older patch when a higher one exists" "${d}" "refs/tags/v${S0}" "${S0}" "${c_s0}"

d="$(clone stable-older-line "v${S0}:${c_s0}" "v${S1}:${c_s1}" "v${NXY}.0:${c_n0}")"
expect_channel "patch on an older line is not Latest" "${d}" "refs/tags/v${S1}" "${S1}" "${c_s1}" stable false
expect_channel "the newer line is Latest" "${d}" "refs/tags/v${NXY}.0" "${NXY}.0" "${c_n0}" stable true

d="$(clone betas-do-not-count "v${S0}:${c_s0}" "v${NXY}.0-beta.1:${c_b1}")"
expect_channel "a newer BETA does not take Latest from a stable" "${d}" "refs/tags/v${S0}" "${S0}" "${c_s0}" stable true

d="$(clone no-release-branch "v${S0}:${c_s0}")"
git -C "${d}" update-ref -d "refs/remotes/origin/release/${XY}"
expect_refused "missing origin/release/${XY} fails closed" "${d}" "refs/tags/v${S0}" "${S0}" "${c_s0}"
git -C "${d}" update-ref -d refs/remotes/origin/main
expect_refused "missing origin/main fails closed" "${d}" "refs/tags/v${B1}" "${B1}" "${c_b1}"

# Line 9 against line 10: a plain `sort` would call 9 the newest.
lit="${work}/lit-src"
git init -q "${lit}"
git -C "${lit}" commit -q --allow-empty -m base
git -C "${lit}" checkout -q -b release/0.9
git -C "${lit}" commit -q --allow-empty -m 0.9.1
c91="$(git -C "${lit}" rev-parse HEAD)"
git -C "${lit}" checkout -q -b release/0.10 main
git -C "${lit}" commit -q --allow-empty -m 0.10.0
c100="$(git -C "${lit}" rev-parse HEAD)"
git -C "${lit}" checkout -q main
git clone -q "${lit}" "${work}/lit"
git -C "${work}/lit" tag v0.10.0 "${c100}"
git -C "${work}/lit" tag v0.9.1 "${c91}"
expect_channel "0.9.1 after 0.10.0 is not Latest (version sort)" "${work}/lit" refs/tags/v0.9.1 0.9.1 "${c91}" stable false

# GITHUB_OUTPUT is appended to.
d="$(clone output "v${S0}:${c_s0}")"
: > "${work}/gh_output"
( cd "${d}" && GITHUB_REF="refs/tags/v${S0}" VERSION="${S0}" GITHUB_SHA="${c_s0}" GITHUB_OUTPUT="${work}/gh_output" RELEASE_GIT_DIR="${d}" bash "${script}" >/dev/null )
if grep -qx 'channel=stable' "${work}/gh_output" && grep -qx 'latest=true' "${work}/gh_output"; then
  ok "channel: answers go to GITHUB_OUTPUT"
else
  bad "channel: answers go to GITHUB_OUTPUT ($(cat "${work}/gh_output"))"
fi

# ── workflow step extraction ─────────────────────────────────────────────────
# step_run <selector> <value>: the run: block of the step whose id is <value> (selector id)
# or whose run: contains <value> (selector contains), dedented. Text-based: no PyYAML.
step_run() {
  python3 -I - "${workflow}" "$1" "$2" <<'PY'
import re, sys
path, sel, val = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path, encoding="utf-8").read().splitlines()
ind = lambda l: len(l) - len(l.lstrip(" "))
steps, cur = [], None
for l in lines:
    m = re.match(r"^(\s*)- (name|id|uses|run|if|env|with|shell|working-directory):", l)
    if m:
        cur = {"indent": len(m.group(1)), "lines": [l]}
        steps.append(cur)
    elif cur is not None and (not l.strip() or ind(l) > cur["indent"]):
        cur["lines"].append(l)
    else:
        cur = None
def run_of(step):
    body = step["lines"]
    for i, l in enumerate(body):
        m = re.match(r"^(\s*)(- )?run: \|\s*$", l)
        if m:
            k = ind(l) + (2 if m.group(2) else 0)
            out = []
            for n in body[i + 1:]:
                if n.strip() and ind(n) <= k:
                    break
                out.append(n)
            while out and not out[-1].strip():
                out.pop()
            d = min(ind(n) for n in out if n.strip())
            return "\n".join(n[d:] for n in out) + "\n"
    return None
for st in steps:
    text = "\n".join(st["lines"])
    r = run_of(st)
    if r is None:
        continue
    if sel == "id" and re.search(r"^\s*(- )?id: " + re.escape(val) + r"\s*$", text, re.M):
        sys.stdout.write(r); sys.exit(0)
    if sel == "contains" and val in r:
        sys.stdout.write(r); sys.exit(0)
sys.exit("no step with %s %r in %s" % (sel, val, path))
PY
}

# ── 2. the version guard, as release.yml runs it ─────────────────────────────
guard="${work}/guard.sh"
if step_run id guard > "${guard}"; then
  ok "workflow: the version guard step (id: guard) is found"
else
  bad "workflow: the version guard step (id: guard) is found"
fi
if grep -F '${{' "${guard}" >/dev/null; then
  bad "workflow: the version guard reads only env vars (a \${{ }} in it would make this test run another script)"
else
  ok "workflow: the version guard reads only env vars"
fi
if grep -F 'merge-base' "${guard}" >/dev/null; then
  bad "workflow: the branch rules live in release-channel.sh, not in the guard"
else
  ok "workflow: the branch rules live in release-channel.sh, not in the guard"
fi

# run_guard <ref> <pom version>: sets rc, gout (GITHUB_OUTPUT) and out (stdout+stderr)
run_guard() {
  local g name type
  g="${work}/g"
  rm -rf "${g}"
  mkdir -p "${g}"
  printf '<?xml version="1.0"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>net.hugmesh</groupId><artifactId>t</artifactId><version>%s</version></project>\n' "$2" > "${g}/pom.xml"
  : > "${g}/out"
  case "$1" in
    refs/tags/*) name="${1#refs/tags/}"; type=tag ;;
    refs/heads/*) name="${1#refs/heads/}"; type=branch ;;
    *) name="$1"; type="" ;;
  esac
  rc=0
  out="$(cd "${g}" && env GITHUB_REF="$1" GITHUB_REF_NAME="${name}" GITHUB_REF_TYPE="${type}" \
    REF="$1" REF_NAME="${name}" REF_TYPE="${type}" VERSION="$2" GITHUB_OUTPUT="${g}/out" \
    bash -e "${guard}" 2>&1)" || rc=$?
  gout="$(cat "${g}/out")"
}
expect_kind() { # name ref version kind
  run_guard "$2" "$3"
  if [ "${rc}" -eq 0 ] && grep -qx "kind=$4" <<< "${gout}" && grep -qx "version=$3" <<< "${gout}"; then
    ok "guard: $1 -> kind=$4"
  else
    bad "guard: $1 -> kind=$4 (rc=${rc}, outputs: ${gout}): ${out}"
  fi
}
expect_guard_refuses() { # name ref version
  run_guard "$2" "$3"
  if [ "${rc}" -ne 0 ] && ! grep -q '^kind=' <<< "${gout}"; then
    ok "guard refuses: $1"
  else
    bad "guard refuses: $1 (rc=${rc}, outputs: ${gout})"
  fi
}
expect_kind "dispatch on main" refs/heads/main "${B1}" main
expect_kind "push to release/${XY}" "refs/heads/release/${XY}" "${S0}" branch
expect_kind "push to release/${XY} carrying the next patch" "refs/heads/release/${XY}" "${S1}" branch
expect_kind "stable tag" "refs/tags/v${S0}" "${S0}" release
expect_kind "beta tag" "refs/tags/v${B1}" "${B1}" release
expect_guard_refuses "release/${XY} with a ${NXY} pom" "refs/heads/release/${XY}" "${NXY}.0"
expect_guard_refuses "release/${NXY} with a ${XY} pom" "refs/heads/release/${NXY}" "${S0}"
expect_guard_refuses "release/${XY}-hotfix" "refs/heads/release/${XY}-hotfix" "${S0}"
expect_guard_refuses "release/${XY}/x" "refs/heads/release/${XY}/x" "${S0}"
expect_guard_refuses "release/foo" refs/heads/release/foo "${S0}"
expect_guard_refuses "a feature branch" refs/heads/feature/x "${B1}"
expect_guard_refuses "a branch that only starts with main" refs/heads/mainline "${B1}"
expect_guard_refuses "a pull request ref" refs/pull/7/merge "${B1}"
expect_guard_refuses "tag does not match the pom" "refs/tags/v${S0}-beta.2" "${B1}"
expect_guard_refuses "stable tag on a beta pom" "refs/tags/v${S0}" "${B1}"
expect_guard_refuses "another artifact's tag prefix" "refs/tags/studio-v${B1}" "${B1}"
expect_guard_refuses "a SNAPSHOT pom on main" refs/heads/main "${S0}-SNAPSHOT"
expect_guard_refuses "a SNAPSHOT pom on release/${XY}" "refs/heads/release/${XY}" "${S0}-SNAPSHOT"

# ── 3. gh release create, as release.yml runs it ─────────────────────────────
create="${work}/create.sh"
if step_run contains 'gh release create' > "${create}"; then
  ok "workflow: the gh release create step is found"
else
  bad "workflow: the gh release create step is found"
fi
mkdir -p "${work}/bin"
cat > "${work}/bin/gh" <<'SH'
#!/usr/bin/env bash
# stub: `gh release view` says "no such release" unless GH_STUB_EXISTS=1; create records argv
if [ "$1 $2" = "release view" ]; then [ "${GH_STUB_EXISTS:-0}" = 1 ]; exit; fi
if [ "$1 $2" = "release create" ]; then printf '%s\n' "$@" > "${GH_STUB_ARGS}"; exit 0; fi
echo "unexpected gh $*" >&2
exit 2
SH
chmod +x "${work}/bin/gh"

# run_create <version> <latest> [exists]: sets rc and args (one argv entry per line)
run_create() {
  local pre
  pre=false
  case "$1" in *-*) pre=true ;; esac
  rm -f "${work}/args"
  rc=0
  ( cd "${work}" && env PATH="${work}/bin:${PATH}" GH_STUB_ARGS="${work}/args" GH_STUB_EXISTS="${3:-0}" \
      GH_TOKEN=x GH_REPO=hugmesh/test GITHUB_REPOSITORY=hugmesh/test TAG="v$1" GITHUB_REF_NAME="v$1" \
      VERSION="$1" PRERELEASE="${pre}" LATEST="$2" bash -e "${create}" >/dev/null 2>&1 ) || rc=$?
  args="$(cat "${work}/args" 2>/dev/null || true)"
}
has_arg() { grep -qx -- "$1" <<< "${args}"; }
run_create "${B1}" false
if [ "${rc}" -eq 0 ] && has_arg --prerelease && has_arg --latest=false && ! has_arg --latest; then
  ok "release: a beta is a prerelease, not Latest"
else
  bad "release: a beta is a prerelease, not Latest (rc=${rc}): ${args}"
fi
run_create "${B1}" true
if [ "${rc}" -eq 0 ] && has_arg --prerelease && has_arg --latest=false && ! has_arg --latest; then
  ok "release: a beta is never Latest, whatever the channel script said"
else
  bad "release: a beta is never Latest, whatever the channel script said (rc=${rc}): ${args}"
fi
run_create "${S0}" true
if [ "${rc}" -eq 0 ] && has_arg --latest && ! has_arg --latest=false && ! has_arg --prerelease && has_arg --verify-tag; then
  ok "release: a stable on the newest line is marked Latest"
else
  bad "release: a stable on the newest line is marked Latest (rc=${rc}): ${args}"
fi
run_create "${S1}" false
if [ "${rc}" -eq 0 ] && has_arg --latest=false && ! has_arg --latest && ! has_arg --prerelease; then
  ok "release: a stable patch on an older line is not Latest"
else
  bad "release: a stable patch on an older line is not Latest (rc=${rc}): ${args}"
fi
run_create "${S0}" ""
if [ "${rc}" -eq 0 ] && has_arg --latest=false && ! has_arg --latest; then
  ok "release: no answer from the channel script is not Latest"
else
  bad "release: no answer from the channel script is not Latest (rc=${rc}): ${args}"
fi
run_create "${S0}" true 1
if [ "${rc}" -eq 0 ] && [ -z "${args}" ]; then
  ok "release: an existing GitHub Release is left alone"
else
  bad "release: an existing GitHub Release is left alone (rc=${rc}): ${args}"
fi

# ── 4. wiring ────────────────────────────────────────────────────────────────
wiring="$(python3 -I - "${workflow}" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
lines = text.splitlines()
code = [l for l in lines if l.strip() and not l.lstrip().startswith("#")]
ind = lambda l: len(l) - len(l.lstrip(" "))
def block(start_re, within=code, depth=None):
    for i, l in enumerate(within):
        if re.fullmatch(start_re, l.strip()) and (depth is None or ind(l) == depth):
            out = []
            for n in within[i + 1:]:
                if ind(n) <= ind(l):
                    break
                out.append(n)
            return out
    return None
def say(ok, name):
    print(("ok   " if ok else "FAIL ") + name)

say(re.search(r"^# hugmesh-release-channels: beta\+stable$", text, re.M) is not None,
    "wiring: the stable-channel marker the org release script looks for")
on = block(r"on:", depth=0) or []
push = block(r"push:", on) or []
say([l.strip() for l in push] == ["branches: ['release/**']", "tags: ['v*']"],
    "wiring: push runs on release/** and v* tags, and on nothing else (no main, no paths)")
say(not any(re.match(r"pull_request", l.strip()) for l in on), "wiring: no pull_request trigger")
say(sorted(l.strip().split(":")[0] for l in on if ind(l) == min(ind(x) for x in on)) == ["push", "workflow_dispatch"],
    "wiring: the only triggers are push and workflow_dispatch")

jobs = block(r"jobs:", depth=0) or []
jd = min(ind(l) for l in jobs)
names = [l.strip().rstrip(":") for l in jobs if ind(l) == jd]
def job(n):
    return "\n".join(block(re.escape(n) + ":", jobs, jd) or [])
version, release = job("version"), job("github-release")
say("fetch-depth: 0" in version, "wiring: the version job checks out with fetch-depth: 0")
say("run: bash scripts/test-release-channel.sh" in version, "wiring: the version job runs this self-test")
say("bash scripts/release-channel.sh" in version, "wiring: the version job runs release-channel.sh")
say("channel: ${{ steps.channel.outputs.channel }}" in version, "wiring: the version job exports the channel")
say("if: needs.version.outputs.kind == 'release'" in release, "wiring: github-release runs only on a release run")
say("fetch-depth: 0" in release, "wiring: github-release checks out with fetch-depth: 0")
i_chan, i_create = release.find("bash scripts/release-channel.sh"), release.find("gh release create")
say(0 <= i_chan < i_create, "wiring: github-release asks release-channel.sh again before gh release create")
say("LATEST: ${{ steps.channel.outputs.latest }}" in release, "wiring: gh release create takes Latest from that fresh answer")
say("needs.version.outputs.latest" not in text, "wiring: no job reads a Latest answer from the version job")

# Every step that runs a maven deploy is gated on kind == 'release' (it or its job), so a
# release/X.Y push and a dispatch on main only verify.
deploys = 0
for n in names:
    body = block(re.escape(n) + ":", jobs, jd) or []
    job_if = any(l.strip() == "if: needs.version.outputs.kind == 'release'" and ind(l) == jd + 2 for l in body)
    steps, cur = [], None
    for l in body:
        if re.match(r"^\s*- ", l) and (cur is None or ind(l) <= cur[0]):
            cur = (ind(l), [l]); steps.append(cur)
        elif cur is not None:
            cur[1].append(l)
    for d, st in steps:
        s = "\n".join(st)
        if re.search(r"(mvn|mvnw)\b[^\n]*\bdeploy\b", s):
            deploys += 1
            gated = job_if or "if: needs.version.outputs.kind == 'release'" in s
            say(gated, "wiring: the deploy in job %s runs only when kind == 'release'" % n)
say(deploys > 0, "wiring: a deploy step was found (the check above did not pass vacuously)")
PY
)"
while IFS= read -r line; do
  case "${line}" in
    "ok   "*) ok "${line#ok   }" ;;
    "FAIL "*) bad "${line#FAIL }" ;;
  esac
done <<< "${wiring}"

echo
echo "release-channel tests: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
