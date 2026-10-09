#!/usr/bin/env bash
# Fresh synthetic Linux runner only; published public artifacts are independently verified.
set -euo pipefail
umask 077
: "${RUNNER_TEMP:?}" "${VERSION:?}" "${GITHUB_REPOSITORY:?}"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?$ ]] || exit 1
root="$RUNNER_TEMP/oauth-projection"
mkdir -p "$root/assets" "$root/docker"
export DOCKER_CONFIG="$root/docker"
export HELM_REGISTRY_CONFIG="$root/anonymous-helm.json"
printf '{}\n' > "$DOCKER_CONFIG/config.json"
gh release view "$VERSION" --repo "$GITHUB_REPOSITORY" --json isDraft > "$root/release.json"
python -c 'import json,sys;assert not json.load(open(sys.argv[1]))["isDraft"]' "$root/release.json"
gh release download "$VERSION" --repo "$GITHUB_REPOSITORY" --dir "$root/assets"
(cd "$root/assets" && sha256sum -c checksums.sha256)
identity="https://github.com/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/heads/main"
cosign verify-blob --bundle "$root/assets/manifest.sigstore.json" --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$root/assets/release-manifest.json"
python - "$root/assets/release-manifest.json" <<'PY'
import hashlib, json, os, re, sys
from pathlib import Path
m = json.load(open(sys.argv[1]))
assert re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?', os.environ['VERSION'])
assert m['controllerVersion'] == os.environ['VERSION']
assert m['chartVersion'] == os.environ['VERSION'][1:]
assert m['image']['reference'] == 'ghcr.io/' + os.environ['GITHUB_REPOSITORY']
assert re.fullmatch('sha256:[0-9a-f]{64}', m['image']['indexDigest'])
assert m['chart']['reference'] == 'ghcr.io/' + os.environ['GITHUB_REPOSITORY_OWNER'] + '/charts/kube-token-requestor'
assert re.fullmatch('sha256:[0-9a-f]{64}', m['chart']['ociDigest'])
assert re.fullmatch('[0-9a-f]{40}', m['sourceCommit'])
package = Path(sys.argv[1]).parent / ('kube-token-requestor-' + os.environ['VERSION'][1:] + '.tgz')
assert hashlib.sha256(package.read_bytes()).hexdigest() == m['chart']['packageSHA256']
for name, asset in m['assets'].items():
    assert Path(name).name == name
    assert hashlib.sha256((Path(sys.argv[1]).parent / name).read_bytes()).hexdigest() == asset['sha256']
PY
image=$(python -c 'import json,sys;m=json.load(open(sys.argv[1]));print(m["image"]["reference"]+"@"+m["image"]["indexDigest"])' "$root/assets/release-manifest.json")
chart=$(python -c 'import json,sys;m=json.load(open(sys.argv[1]));print(m["chart"]["reference"]+"@"+m["chart"]["ociDigest"])' "$root/assets/release-manifest.json")
cosign verify --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$image" > "$root/image-verification.json"
cosign verify --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$chart" > "$root/chart-verification.json"
export REQUESTOR_OIDC_API=1
export REQUESTOR_OIDC_CONTROLLER_IMAGE="$image"
export REQUESTOR_OIDC_CONTROLLER_CHART="$root/assets/kube-token-requestor-${VERSION#v}.tgz"
go install sigs.k8s.io/kind@v0.33.0
go test -v -count=1 -timeout=28m ./integration/oidc -run '^TestActualKubernetes$'
python - "$root/assets/release-manifest.json" "$root/evidence.json" <<'PY'
import json, os, platform, sys
m = json.load(open(sys.argv[1]))
json.dump({'controllerVersion':m['controllerVersion'], 'sourceCommit':m['sourceCommit'],
           'harnessCommit':os.environ['GITHUB_SHA'], 'architecture':{'x86_64':'amd64', 'aarch64':'arm64'}[platform.machine()],
           'kubernetes':'1.35.8', 'provider':'OAuthTokenExchange',
           'twoUnchangedReadyControllerPods':True, 'boundPodSubjectProjectionRotation':True,
           'validConsumerPublicationAfterSubjectRotation':True, 'stoppedCAUnchanged':True,
           'subjectProjectionSeconds':600, 'topology':'synthetic co-located management/child API',
           'scope':'released controller and actual kubelet projection; no actual CA process or vendor product',
           'naturalLifetimeAcceptance':False}, open(sys.argv[2], 'w'), indent=2)
PY
