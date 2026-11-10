#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# release-channel.sh: the release channel of one run of .github/workflows/release.yml
# for a net.hugmesh Maven library. The same file is in hugmesh-build-config,
# hugmesh-parent, hugmesh-commons and hugmesh-auth-core; keep the four copies equal.
#
# THE TAG DECIDES THE CHANNEL:
#
#   ref                        channel  rule
#   refs/heads/main            none     verify only, nothing is deployed
#   refs/heads/release/X.Y     none     verify only; pom.xml must be X.Y.something (this
#                                       is the push run the org release script requires to
#                                       be green before it tags release/X.Y)
#   refs/tags/vX.Y.Z-beta.N    beta     the tagged commit must be on origin/main; the
#                                       GitHub Release is a prerelease, never Latest
#   refs/tags/vX.Y.Z           stable   the tagged commit must be on origin/release/X.Y;
#                                       refused when a higher vX.Y.W tag already exists.
#                                       latest=true only when X.Y is the newest stable line
#                                       among this repo's vA.B.C tags (sort -V, the tag
#                                       being released ignored), so a patch on an older
#                                       line is never marked Latest
#   any other ref or tag       refused  (-rc.N and every other prerelease have no channel)
#
# Every tag must be exactly "v" + VERSION. A missing origin/main or origin/release/X.Y
# fails closed: the workflow checks out with fetch-depth: 0 so both exist.
#
# Inputs (environment):
#   GITHUB_REF       required
#   VERSION          required: pom.xml's <project><version>, as the version guard read it
#   GITHUB_SHA       the commit being released (default HEAD)
#   RELEASE_GIT_DIR  the git checkout to read (default: the current directory)
#
# Prints channel=... and latest=..., and appends them to $GITHUB_OUTPUT when that is set.
# No network: the answer comes from the checkout's own branches and tags. The version job
# runs it to refuse early; the github-release job runs it again right before
# `gh release create`, so a re-run never marks an older line Latest.
#
# Test: bash scripts/test-release-channel.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REF="${GITHUB_REF:?GITHUB_REF must be set}"
VERSION="${VERSION:?VERSION must be set (pom.xml <project><version>)}"
SHA="${GITHUB_SHA:-HEAD}"
GIT_DIR_="${RELEASE_GIT_DIR:-.}"

die() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

beta_tag_re='^v([0-9]+)\.([0-9]+)\.([0-9]+)-beta\.[1-9][0-9]*$'
stable_tag_re='^v([0-9]+)\.([0-9]+)\.([0-9]+)$'
release_branch_re='^release/([0-9]+)\.([0-9]+)$'

# on_branch <commit> <branch>: 0 when <commit> is on origin/<branch>. Dies when that
# remote-tracking branch is absent: no branch, no release.
on_branch() {
  local c b ref
  c="$1"
  b="$2"
  ref="refs/remotes/origin/${b}"
  git -C "${GIT_DIR_}" rev-parse -q --verify "${ref}^{commit}" >/dev/null 2>&1 \
    || die "branch ${b} is not in the checkout (no ${ref}). It does not exist on origin, or the workflow did not check out with fetch-depth: 0. Nothing is published."
  git -C "${GIT_DIR_}" merge-base --is-ancestor "${c}" "${ref}"
}

channel=none
latest=false

case "${REF}" in
  refs/heads/main)
    ;;
  refs/heads/release/*)
    branch="${REF#refs/heads/}"
    [[ "${branch}" =~ ${release_branch_re} ]] \
      || die "release branch ${branch} is not named release/X.Y (for example release/2.2). Nothing is published."
    bxy="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
    case "${VERSION}" in
      "${bxy}".*) ;;
      *) die "pom.xml version ${VERSION} is not on the ${bxy} line, but this is ${branch}. A release/X.Y branch carries X.Y.* only." ;;
    esac
    ;;
  refs/tags/v*)
    tag="${REF#refs/tags/}"
    [ "${tag}" = "v${VERSION}" ] \
      || die "tag ${tag} does not match pom.xml version ${VERSION}. Tag v${VERSION}, or change pom.xml in a PR first."
    commit="$(git -C "${GIT_DIR_}" rev-parse -q --verify "${SHA}^{commit}" 2>/dev/null)" \
      || die "commit ${SHA} is not in the checkout (${GIT_DIR_}). The workflow must check out with fetch-depth: 0."
    if [[ "${tag}" =~ ${beta_tag_re} ]]; then
      channel=beta
      on_branch "${commit}" main \
        || die "beta tag ${tag} is on commit ${commit}, which is not on main. A beta (vX.Y.Z-beta.N) is cut from main only; release/X.Y publishes stable vX.Y.Z tags."
    elif [[ "${tag}" =~ ${stable_tag_re} ]]; then
      channel=stable
      major="${BASH_REMATCH[1]}"
      minor="${BASH_REMATCH[2]}"
      patch="${BASH_REMATCH[3]}"
      xy="${major}.${minor}"
      on_branch "${commit}" "release/${xy}" \
        || die "stable tag ${tag} is on commit ${commit}, which is not on release/${xy}. A stable vX.Y.Z is cut from its own release/X.Y branch only (never from main, never from another line's branch)."
      lines=("${xy}")
      while IFS= read -r t; do
        [[ "${t}" =~ ${stable_tag_re} ]] || continue
        [ "${t}" = "${tag}" ] && continue
        lines+=("${BASH_REMATCH[1]}.${BASH_REMATCH[2]}")
        if [ "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}" = "${xy}" ] && (( 10#${BASH_REMATCH[3]} > 10#${patch} )); then
          die "stable ${t} already exists on the ${xy} line, so ${tag} is older. Fix forward with a higher patch."
        fi
      done < <(git -C "${GIT_DIR_}" tag -l 'v*')
      newest="$(printf '%s\n' "${lines[@]}" | sort -V | tail -n 1)"
      if [ "${newest}" = "${xy}" ]; then
        latest=true
      fi
    else
      die "tag ${tag} names no release channel. Release tags are vX.Y.Z-beta.N (beta, from main) or vX.Y.Z (stable, from release/X.Y); -rc.N and every other prerelease are refused."
    fi
    ;;
  *)
    die "release runs only on refs/heads/main, refs/heads/release/X.Y or a refs/tags/v<version> tag, not ${REF}. Nothing is published."
    ;;
esac

printf 'channel=%s\nlatest=%s\n' "${channel}" "${latest}"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'channel=%s\nlatest=%s\n' "${channel}" "${latest}" >> "${GITHUB_OUTPUT}"
fi
