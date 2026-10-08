# Synthetic local acceptance

Tests use three explicitly named kind clusters: `requestor-management` (two nodes),
`requestor-child-a` and `requestor-child-b`. Never reuse an external kubeconfig/current context.
The harness rejects non-loopback API addresses, exec/auth-provider plugins, insecure TLS and
nodes outside these names. Generated kubeconfigs and credentials stay in a protected temporary
directory outside the source checkout. Tokens are created by real local Kubernetes APIs and
remain in API Secrets or process memory; test output contains counts/conditions only.

Pinned baseline: kind v0.33.0, node v1.35.8, Go 1.26.9/client-go v0.35.9, Helm v4.1.3,
Prometheus/promtool v3.15.0. Actual upstream CA baseline is v1.35.2. Record each actual digest
from registry outputs and pass it explicitly; synthetic stopped-image hashes are not releases.

`go run ./integration/local` supports these actions:

- `bootstrap`: create exact synthetic identities/grants, two child issuer sources, three owned
  output Secrets and three stopped CA fixtures; generate non-secret Helm values. It requires
  fresh local clusters and does not overwrite existing resources.
- `assert`: validate three distinct issued tokens using actual child API identities/UIDs and
  allowed/denied permissions. CA fixtures must remain stopped.
- `configure-ca`: while controller/CA fixtures are stopped, configure actual digest-pinned CA
  containers, normal TokenFile volumes, read-only management CAPI discovery and frequent renewal.
- `observe`: read-only, verify the first actual CA Pod has no replacement/restarts, repeated
  restricted API access, at least two token changes, rejection of the original token after
  its actual expiry and absence of authentication/authorization failures in recent CA logs.

Arguments are `--kubeconfigs` (protected directory containing `management`, `child-a`, `child-b`),
`--values` (non-secret generated values), `--ca-digest` and `--duration` for observation. Observation
requires at least eleven minutes and emits no credential payloads. It is accelerated reload
acceptance, not the required 48-hour natural-lifetime adoption evidence.

`integration/fixtures/capi-crds.json` is a minimal empty local discovery fixture. It installs no
CAPI controllers, node pools or VM resources. It must never be applied to an operator cluster.
The actual CA therefore scans an empty discovered fleet and has no management scaling grants.
This test proves authentication/reload behavior, not node provisioning or autoscaling performance.

Run chart rendering, alert syntax/firing fixtures and race checks with Helm/promtool on PATH.
Local Helm upgrade/uninstall acceptance additionally checks retained runtime ConfigMap/Lease
UIDs and state; rendering tests alone cannot prove Kubernetes/Helm lifecycle behavior.
