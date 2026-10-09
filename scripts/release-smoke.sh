#!/usr/bin/env bash
# Fresh runner only: no registry login, external kubeconfigs or real deployment targets.
set -euo pipefail
: "${RUNNER_TEMP:?}" "${VERSION:?}" "${IMAGE:?}" "${CHART:?}" "${ARCH:?}"
export DOCKER_CONFIG="$RUNNER_TEMP/anonymous-docker"
export HELM_REGISTRY_CONFIG="$RUNNER_TEMP/anonymous-helm.json"
mkdir -p "$DOCKER_CONFIG"
printf '{}\n' > "$DOCKER_CONFIG/config.json"
(cd dist && sha256sum -c checksums.sha256)
IMAGE_DIGEST=$(python -c 'import json;print(json.load(open("dist/release-manifest.json"))["image"]["indexDigest"])')
CHART_DIGEST=$(python -c 'import json;print(json.load(open("dist/release-manifest.json"))["chart"]["ociDigest"])')
identity="https://github.com/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/heads/main"
cosign verify --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$IMAGE@$IMAGE_DIGEST" > "$RUNNER_TEMP/image-verification.json"
cosign verify --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$CHART@$CHART_DIGEST" > "$RUNNER_TEMP/chart-verification.json"
cosign verify-blob --bundle dist/manifest.sigstore.json --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com dist/release-manifest.json
mkdir -p "$RUNNER_TEMP/license-bundle"
tar -xzf dist/licenses.tgz -C "$RUNNER_TEMP/license-bundle"
license_container=$(docker create --platform "linux/$ARCH" --network none "$IMAGE@$IMAGE_DIGEST" version)
trap 'docker rm "$license_container" >/dev/null' EXIT
docker cp "$license_container:/licenses" "$RUNNER_TEMP/image-licenses"
docker rm "$license_container" >/dev/null
trap - EXIT
diff -r "$RUNNER_TEMP/license-bundle/licenses" "$RUNNER_TEMP/image-licenses"
cmp LICENSE "$RUNNER_TEMP/image-licenses/PROJECT-LICENSE"
cmp NOTICE "$RUNNER_TEMP/image-licenses/PROJECT-NOTICE"
test -s "$RUNNER_TEMP/image-licenses/GO-LICENSE"
actual=$(docker run --rm --platform "linux/$ARCH" --read-only --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges --network none "$IMAGE@$IMAGE_DIGEST" version)
test "$actual" = "${VERSION#v}"
docker run --rm -i --platform "linux/$ARCH" --read-only --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges --network none "$IMAGE@$IMAGE_DIGEST" validate-config < examples/registry.json
mkdir -p "$RUNNER_TEMP/pulled"
helm pull "oci://$CHART" --version "${VERSION#v}" --destination "$RUNNER_TEMP/pulled" > "$RUNNER_TEMP/chart-pull" 2>&1
grep -Fq "$CHART_DIGEST" "$RUNNER_TEMP/chart-pull"
package="$RUNNER_TEMP/pulled/kube-token-requestor-${VERSION#v}.tgz"
cmp "$package" "dist/kube-token-requestor-${VERSION#v}.tgz"
tar -xOf "$package" kube-token-requestor/LICENSE | cmp - LICENSE
tar -xOf "$package" kube-token-requestor/NOTICE | cmp - NOTICE
go install sigs.k8s.io/kind@v0.33.0
cat > "$RUNNER_TEMP/kind.yaml" <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
YAML
export KUBECONFIG="$RUNNER_TEMP/release-kubeconfig"
kind create cluster --name requestor-release --config "$RUNNER_TEMP/kind.yaml" --image kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0 --wait 2m
context=kind-requestor-release
uid=$(kubectl --context "$context" get namespace kube-system -o jsonpath='{.metadata.uid}')
helm --kube-context "$context" install requestor "$package" --namespace requestor-test --create-namespace --set registry.managementUID="$uid" --set replicaCount=2 --set networkPolicy.enabled=false --wait --timeout 3m
base=(kubectl --context "$context" --namespace requestor-test)
status_name=requestor-kube-token-requestor-status
lease_name=requestor-kube-token-requestor
state_uid=$("${base[@]}" get configmap "$status_name" -o jsonpath='{.metadata.uid}')
lease_uid=$("${base[@]}" get lease "$lease_name" -o jsonpath='{.metadata.uid}')
# Wait for the accepted generation to be persisted before comparing stable runtime bytes.
for attempt in {1..20}; do
  "${base[@]}" get configmap "$status_name" -o jsonpath='{.data.state\.json}' > "$RUNNER_TEMP/state-before.json"
  if python -c 'import json,sys;s=json.load(open(sys.argv[1]));assert s["generation"] and s["schemaVersion"]==1' "$RUNNER_TEMP/state-before.json" 2>/dev/null; then break; fi
  sleep 1
done
python -c 'import json,sys;assert json.load(open(sys.argv[1]))["generation"]' "$RUNNER_TEMP/state-before.json"
helm --kube-context "$context" upgrade requestor "$package" --namespace requestor-test --reuse-values --wait --timeout 3m
assert_state() {
  test "$("${base[@]}" get configmap "$status_name" -o jsonpath='{.metadata.uid}')" = "$state_uid"
  test "$("${base[@]}" get lease "$lease_name" -o jsonpath='{.metadata.uid}')" = "$lease_uid"
  "${base[@]}" get configmap "$status_name" -o jsonpath='{.data.state\.json}' > "$RUNNER_TEMP/state-after.json"
  cmp "$RUNNER_TEMP/state-before.json" "$RUNNER_TEMP/state-after.json"
}
assert_state
helm --kube-context "$context" uninstall requestor --namespace requestor-test --wait --timeout 2m
assert_state
helm --kube-context "$context" install requestor "$package" --namespace requestor-test --set registry.managementUID="$uid" --set replicaCount=2 --set networkPolicy.enabled=false --wait --timeout 3m
assert_state
printf '{"platform":"linux/%s","anonymousPull":true,"signaturesVerified":true,"nativeStartup":true,"helmInstallUpgradeUninstallReinstall":true,"runtimeUIDsAndStatePreserved":true,"scope":"synthetic empty local fleet"}\n' "$ARCH" > "dist/smoke-$ARCH.json"
