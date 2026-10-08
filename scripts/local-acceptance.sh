#!/usr/bin/env bash
# Fresh runner only. All Kubernetes resources belong to synthetic loopback kind clusters.
set -euo pipefail
umask 077
: "${RUNNER_TEMP:?}" "${VERSION:?}" "${ARCH:?}" "${GITHUB_REPOSITORY:?}"
root="$RUNNER_TEMP/local-acceptance"
mkdir -p "$root/assets" "$root/kubeconfigs" "$root/docker"
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
assert m['image']['platformDigests']['linux/' + os.environ['ARCH']]
assert re.fullmatch('[0-9a-f]{40}', m['sourceCommit'])
for name, asset in m['assets'].items():
    assert Path(name).name == name
    assert hashlib.sha256((Path(sys.argv[1]).parent / name).read_bytes()).hexdigest() == asset['sha256']
PY
image=$(python -c 'import json,sys;m=json.load(open(sys.argv[1]));print(m["image"]["reference"]+"@"+m["image"]["indexDigest"])' "$root/assets/release-manifest.json")
cosign verify --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$image" > "$root/image-verification.json"
go install sigs.k8s.io/kind@v0.33.0
go build -o "$root/harness" ./integration/local
cat > "$root/management.yaml" <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
YAML
node=kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0
kind create cluster --name requestor-management --config "$root/management.yaml" --kubeconfig "$root/kubeconfigs/management" --image "$node" --wait 2m
for role in child-a child-b; do
  kind create cluster --name "requestor-$role" --kubeconfig "$root/kubeconfigs/$role" --image "$node" --wait 2m
done
ca_digest=sha256:aac369dc283927a623deb1af54696efcc722ae79255aa07788422e495bab887d
args=(--kubeconfigs "$root/kubeconfigs" --values "$root/values.json")
"$root/harness" --action bootstrap --ca-digest "$ca_digest" "${args[@]}"
package="$root/assets/kube-token-requestor-${VERSION#v}.tgz"
helm --kube-context kind-requestor-management --kubeconfig "$root/kubeconfigs/management" install requestor "$package" --namespace requestor-test -f "$root/values.json" --set replicaCount=2 --wait --timeout 3m
base=(kubectl --kubeconfig "$root/kubeconfigs/management" --context kind-requestor-management -n requestor-test)
test "$("${base[@]}" get deployment requestor-kube-token-requestor -o jsonpath='{.spec.template.spec.containers[0].image}')" = "$image"
accepted=false
for attempt in {1..20}; do
  if "$root/harness" --action assert "${args[@]}"; then accepted=true; break; fi
  sleep 5
done
test "$accepted" = true
"${base[@]}" scale deployment/requestor-kube-token-requestor --replicas=0
"${base[@]}" wait --for=delete pod -l app.kubernetes.io/name=kube-token-requestor --timeout=90s
"${base[@]}" apply -f integration/fixtures/capi-crds.json
"$root/harness" --action configure-ca --ca-digest "$ca_digest" "${args[@]}"
helm --kube-context kind-requestor-management --kubeconfig "$root/kubeconfigs/management" upgrade requestor "$package" --namespace requestor-test -f "$root/values.json" --set replicaCount=2 --wait --timeout 3m
"${base[@]}" scale deployment/child-a-ca-one --replicas=1
"${base[@]}" rollout status deployment/child-a-ca-one --timeout=3m
"$root/harness" --action observe --duration 13m "${args[@]}"
"$root/harness" --action faults "${args[@]}"
python - "$root/assets/release-manifest.json" "$root/evidence.json" <<'PY'
import json, os, sys
m = json.load(open(sys.argv[1]))
json.dump({'controllerVersion':m['controllerVersion'], 'sourceCommit':m['sourceCommit'],
           'harnessCommit':os.environ['GITHUB_SHA'], 'architecture':os.environ['ARCH'],
           'managementKubernetes':'1.35.8', 'childKubernetes':'1.35.8',
           'clusterAutoscaler':'1.35.2', 'provider':'SecretIssuer', 'reloadPolicy':'TokenFile',
           'realIdentityAndRBAC':True, 'sameCAPodTwoRotationsOldTokenRejected':True,
           'issuerAndStoppedConsumerIsolation':True, 'scope':'synthetic empty CAPI fleet',
           'acceleratedLifetimeSeconds':600, 'naturalLifetimeAcceptance':False},
          open(sys.argv[2], 'w'), indent=2)
PY
