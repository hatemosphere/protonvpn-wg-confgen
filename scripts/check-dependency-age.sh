#!/usr/bin/env bash
# Fails when a change pins a dependency version published less than
# MIN_AGE_DAYS (default 7) ago. Hijacked releases are usually caught and pulled
# within days, so a week of waiting keeps most of them out. Covers Go modules
# (new go.sum lines and go run/install pins), GitHub Actions (new uses: SHA
# pins), tool versions annotated with their repository ("version: v1.2.3 #
# owner/repo") and Docker Hub images (new @sha256 pins). Needs go, gh, jq and
# curl. Usage: check-dependency-age.sh <base-ref>
#
# Publish times: actions use the release's time and images the tag's push time,
# both recorded by the server, after checking that the pin is that release or
# tag. Go modules use the module proxy's time, which is the tagged commit's and
# could be backdated; the checksum database and the capability diff in CI are
# the other layers there.
set -euo pipefail

base=$1
cutoff=$(( $(date +%s) - ${MIN_AGE_DAYS:-7} * 86400 ))
status=0

added() { git diff -U0 "$base" -- "$@" | grep '^+[^+]' | cut -c2- || true; }
epoch() { jq -rn --arg t "$1" '$t | sub("\\.[0-9]+"; "") | fromdate'; }
check() { # name, publish time
  local ts
  ts=$(epoch "$2" 2>/dev/null) || ts=
  if ! [[ $ts =~ ^[0-9]+$ ]]; then
    echo "FAIL $1: no usable publish time (${2:-none})"; status=1
  elif [ "$ts" -gt "$cutoff" ]; then
    echo "FAIL $1: published $2, younger than ${MIN_AGE_DAYS:-7} days"; status=1
  else
    echo "ok   $1: published $2"
  fi
}

# A go run/install pin names a package; its module is the longest prefix the
# proxy knows.
modtime() {
  local path=$1
  while :; do
    go list -m -json "$path@$2" 2>/dev/null | jq -r .Time && return
    [[ $path == */* ]] || return 0
    path=${path%/*}
  done
}

while read -r module version; do
  check "$module@$version" "$(modtime "$module" "$version")"
done < <({
  added go.sum | awk '{print $1, $2}'
  added .github scripts Makefile | grep -oE 'go (run|install) [^ @]+@v[^ ]+' | awk '{split($3, m, "@"); print m[1], m[2]}'
} | sed 's#/go.mod$##' | sort -u)

while read -r repo sha tag; do
  repo=$(cut -d/ -f1-2 <<<"$repo")
  if [ "$(gh api "repos/$repo/commits/$tag" --jq .sha 2>/dev/null)" != "$sha" ]; then
    echo "FAIL $repo@$sha: not the commit of $tag"; status=1; continue
  fi
  check "$repo@$tag" "$(gh api "repos/$repo/releases/tags/$tag" --jq .published_at 2>/dev/null)"
done < <(added .github/workflows .github/actions | sed -nE 's/.*uses: *([^@ ]+)@([0-9a-f]{40}) *# *([^ ]+).*/\1 \2 \3/p' | sort -u)

while read -r version repo; do
  published=$(gh api "repos/$repo/releases/tags/$version" --jq .published_at 2>/dev/null) ||
    published=$(gh api "repos/$repo/releases/tags/v$version" --jq .published_at 2>/dev/null) ||
    published=
  check "$repo@$version" "$published"
done < <(added .github | sed -nE 's/.*: *"?([v0-9][^" ]*)"? *# *([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+) *$/\1 \2/p' | sort -u)

while read -r image tag digest; do
  [[ $image == */* ]] || image=library/$image
  info=$(curl -fsS "https://hub.docker.com/v2/repositories/$image/tags/$tag")
  if [ "$(jq -r .digest <<<"$info")" != "$digest" ]; then
    echo "FAIL $image:$tag: $digest is not the tag's current digest"; status=1; continue
  fi
  check "$image:$tag" "$(jq -r .tag_last_pushed <<<"$info")"
done < <(added test scripts | grep -oE '[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' | sed -E 's/:([^@]+)@/ \1 /' | sort -u)

exit $status
