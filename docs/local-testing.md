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
- `failover`: delete only the actual UID-pinned synthetic leader Pod, verify a new holder on the
  same Lease and two ready controller Pods within 90 seconds, then confirm all three outputs
  renew without expiry rollback and the durable status and actual CA Pod retain their UIDs.
  This tests real Pod/Lease failover; node loss and instruction-level crash injection are separate.
- `assert`: validate three distinct issued tokens using actual child API identities/UIDs and
  issuer/consumer effective rules and allowed/denied permissions. CA fixtures must remain stopped.
- `rights`: the same read-only identity and permission checks with active CA fixtures allowed.
- `configure-ca`: while controller/CA fixtures are stopped, configure actual digest-pinned CA
  containers, normal TokenFile volumes, read-only management CAPI discovery and frequent renewal.
- `observe`: read-only, verify the first actual CA Pod has no replacement/restarts, repeated
  restricted API access, at least two token changes, rejection of the original token after
  its actual expiry (with a bounded two-minute rejection grace) and absence of authentication/authorization failures in recent CA logs.
- `faults`: require the accelerated two-child baseline and a stopped second consumer; temporarily
  expire child-a's issuer rotation annotation, prove child-b continues rotating, restore it and
  verify recovery. Then temporarily replace only the stopped consumer's ownership annotation
  and prove the sibling rotates without overwriting the foreign-owned output. Annotation changes
  use UID/resourceVersion/value CAS and cleanup reports failure. No credential data is changed.
- `partition`: verify both actual child UIDs and the kind ownership/role labels of the exact
  `requestor-child-a-control-plane` container, then pause only that container for five minutes.
  After draining in-flight calls, require its output to stay unchanged while child-b rotates at
  least twice. Unpause even on failure, require issuance recovery within 150 seconds and recheck
  the original child UID. The accelerated fixture starts with at least eight minutes of remaining
  token lifetime; this is transport isolation, not an expiry/safety-stop or VM provisioning drill.

- `stop-start`: require a stopped, unlatched second consumer with no outstanding restart intent;
  stop and drain the local requestor for a guarded reload-policy handoff, then observe three
  distinct Ready CA Pod identities (initial plus two replacements). Manually suspend that CA
  and prove it remains stopped through another renewal. Cleanup drains it and the requestor,
  restores the original registry bytes and TokenFile policy, and returns requestor replicas to
  two. A failed run may leave a latched safety stop requiring reviewed recovery; do not erase
  runtime state or automatically acknowledge it to force a rerun.

- `revoke-issuer`: in the accelerated synthetic fixture, validate a new restricted child-a
  issuer token, CAS-adopt it into the same management source UID, delete only the pinned
  predecessor child token Secret and prove old API authentication fails. Both children must
  rotate and the active CA Pod must stay Ready with the same UID. Once adopted, keep the new
  restricted source; never restore the revoked predecessor. A rerun requires fresh fixtures.

Arguments are `--kubeconfigs` (protected directory containing `management`, `child-a`, `child-b`),
`--values` (non-secret generated values), `--ca-digest` and `--duration` for observation. Observation
requires at least thirteen minutes and emits no credential payloads. It is accelerated reload
acceptance, not the required 48-hour natural-lifetime adoption evidence.

`integration/fixtures/capi-crds.json` is a minimal empty local discovery fixture. It installs no
CAPI controllers, node pools or VM resources. It must never be applied to an operator cluster.
The actual CA therefore scans an empty discovered fleet and has no management scaling grants.
This test proves authentication/reload behavior, not node provisioning or autoscaling performance.

Run chart rendering, alert syntax/firing fixtures and race checks with Helm/promtool on PATH.
Local Helm upgrade/uninstall acceptance additionally checks retained runtime ConfigMap/Lease
UIDs and state; rendering tests alone cannot prove Kubernetes/Helm lifecycle behavior.

## Natural-policy observation

`observe-natural` is a separate fail-closed 48–49 hour harness. Prepare a reviewed local-only
registry with 24-hour requested tokens, accepted TTL 22–25 hours, renewal 1–12 hours before
expiry, stop at least 30 minutes before expiry and clock tolerance at most one minute. Drain the
requestor for that material handoff and validate newly published 24-hour tokens before starting.
Use a fixed published image/chart throughout. Verify release checksums and Sigstore signatures
before passing `--manifest`; the harness does not substitute for signature verification.

Pass `--duration 48h --manifest <verified-release-manifest> --evidence <task-directory>/natural-evidence.json`.
The evidence file must be in the parent of the protected task kubeconfig directory. It records
only public artifact identity, timestamps, rotation counts and the synthetic CA Pod UID, using
an atomic checkpoint. A sleep/observation gap over 90 seconds, image/registry change, missing
controller replica, CA restart, API/rights failure or missing old-token rejection fails the run.
Interrupted runs are not resumed or combined; start a fresh observation. Keep the host awake and
Docker/three local clusters available. Running checkpoints are not passed acceptance reports.

This result alone is not a stable promotion report: capacity, OAuth, fault/alert and operator
adoption gates remain separate. Do not publish local kubeconfigs or credential payloads.
