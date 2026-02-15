#!/usr/bin/env bash
set -euo pipefail

TAG="${TAG:-${1:-}}"
if [[ -z "${TAG}" ]]; then
  echo "Usage: TAG=v0.1.0 scripts/github_release.sh"
  echo "  or:  scripts/github_release.sh v0.1.0"
  exit 2
fi

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "Missing GITHUB_TOKEN env var (GitHub fine-grained token with 'Contents: Read and write' for the repo)."
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq not found"
  exit 2
fi

if [[ ! -d dist ]]; then
  echo "dist/ not found; run: make release"
  exit 2
fi

mapfile -t ASSETS < <(ls -1 dist/*.tgz dist/*.sha256 2>/dev/null || true)
if [[ "${#ASSETS[@]}" -eq 0 ]]; then
  echo "No assets found in dist/ (*.tgz, *.sha256). Run: make release"
  exit 2
fi

origin_url="$(git remote get-url origin)"
if [[ "${origin_url}" =~ github\.com[:/]+([^/]+)/([^/.]+)(\.git)?$ ]]; then
  owner="${BASH_REMATCH[1]}"
  repo="${BASH_REMATCH[2]}"
else
  echo "Cannot parse GitHub owner/repo from origin: ${origin_url}"
  exit 2
fi

api="https://api.github.com"
auth_header="Authorization: Bearer ${GITHUB_TOKEN}"
accept_header="Accept: application/vnd.github+json"

target_commitish="$(git rev-parse --abbrev-ref HEAD)"
title="${TITLE:-${TAG}}"
notes="${NOTES:-Release ${TAG}}"

create_payload="$(jq -cn \
  --arg tag_name "${TAG}" \
  --arg target_commitish "${target_commitish}" \
  --arg name "${title}" \
  --arg body "${notes}" \
  '{tag_name:$tag_name,target_commitish:$target_commitish,name:$name,body:$body,draft:false,prerelease:false,generate_release_notes:false}')"

resp="$(curl -sS -X POST \
  -H "${auth_header}" -H "${accept_header}" \
  "${api}/repos/${owner}/${repo}/releases" \
  -d "${create_payload}" || true)"

upload_url="$(echo "${resp}" | jq -r '.upload_url // empty')"
html_url="$(echo "${resp}" | jq -r '.html_url // empty')"
release_id="$(echo "${resp}" | jq -r '.id // empty')"

if [[ -z "${upload_url}" || -z "${release_id}" ]]; then
  # If release already exists, fetch it by tag.
  message="$(echo "${resp}" | jq -r '.message // empty')"
  if [[ "${message}" == "Validation Failed" ]]; then
    resp2="$(curl -sS -X GET \
      -H "${auth_header}" -H "${accept_header}" \
      "${api}/repos/${owner}/${repo}/releases/tags/${TAG}")"
    upload_url="$(echo "${resp2}" | jq -r '.upload_url // empty')"
    html_url="$(echo "${resp2}" | jq -r '.html_url // empty')"
    release_id="$(echo "${resp2}" | jq -r '.id // empty')"
  fi
fi

if [[ -z "${upload_url}" || -z "${release_id}" ]]; then
  echo "Failed to create/find release. API response:"
  echo "${resp}" | jq .
  exit 1
fi

# upload_url is a URI template: ".../assets{?name,label}"
upload_url="${upload_url%\{*}"

for f in "${ASSETS[@]}"; do
  name="$(basename "${f}")"
  echo "Uploading ${name}..."
  curl -sS -X POST \
    -H "${auth_header}" \
    -H "Content-Type: application/octet-stream" \
    "${upload_url}?name=${name}" \
    --data-binary "@${f}" >/dev/null
done

echo "Release ready: ${html_url:-https://github.com/${owner}/${repo}/releases/tag/${TAG}}"

