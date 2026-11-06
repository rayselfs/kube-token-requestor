# Access token publication (unreleased)

An explicit `access` object selects the Access consumer in the existing requestor. See
[disabled synthetic enrollment](../examples/access-registry.json). Legacy CA configurations
retain their existing semantics. The published v0.2.0 does not support this enrollment.

## Authority

Use `permissionProfile: access-impersonation`, `reloadPolicy: TokenFile`, finite non-system
users/groups and no caDeployment or leaderElectionLease. Target RBAC must grant only those
named impersonation subjects, exact identity verification reads and Kubernetes default
self-review/discovery access. Never grant wildcards, token minting, workload reads/writes or
CA rights to the gateway SA. The issuer remains separate and may mint only enrolled SAs.
Requestor validates effective rules in the identity namespace; independently review other
namespace bindings. It does not provision target RBAC or infer per-user workload grants.

## Publication and recovery

Output remains a pre-existing UID-pinned Opaque Secret with ca.crt/token and the existing
owner annotation. Requestor is its only automated writer. Core mounts its directory read-only,
without subPath. Secret encryption, access control and projection/reload acceptance are required.
ESO/Vault can deliver other inputs but must not overwrite this output.

CredentialPublished means authenticated token publication, not gateway Ready. AccessDisabled
stops publication, not existing API sessions. AccessBlocked latches an unsafe lifetime or
invalid consumer authority; no Deployment is read, patched or scaled. Automatic rescue of a
revoked identity is prohibited. Recover through independently authorized replacement of the
valid output token and a fresh UUID `token-requestor.io/acknowledge-stop` annotation. Do not reuse a
previous acknowledgement. The same output UID, owner and CA remain required.

## Activation boundary

This publisher does not revoke already-issued tokens or terminate API streams. A separately
qualified gateway admission and operator stream-termination procedure must enforce the Access RFC bounds;
Secret deletion or token expiry alone is not termination. An authorized emergency edge restart may interrupt other users; automatic selective termination is not required by this publisher. Never activate this feature as a
complete Access service based only on publisher tests. First deployment should use an isolated
Access-only release, registry, lease and outputs, leaving existing CA requestors untouched.

Hot removal and rebinding of Access consumers are deliberately rejected: the requestor cannot
prove external route/stream revocation. Until that receipt contract exists, retirement requires
an operator-reviewed stop of the isolated Access release after route/target revocation, then
explicit reconstruction of its retained registry/status state. Do not attempt this with a shared
CA release. No automatic cleanup or fallback issuer is provided. Removing the old credential PVC
is conditional on complete replacement-path acceptance; the candidate chart is not changed here.

## Validation

Run normal repository Go race/vet, specification and Helm checks. `TestAccessPublicationAndIsolation`
uses synthetic HTTPS responses to cover rotation, disable, expiry, revoked authority, wrong Secret
UID, stale generation, provider outage and retained latch. `TestAccessNativeAPI` additionally
requires REQUESTOR_ACCESS_TEST_KUBECONFIG and the exact isolated loopback kind fixture named in
that test; it checks real TokenRequest/RBAC/CAS and excessive-grant rejection, not a deployed
controller/SSO/revocation composition. Never substitute a company kubeconfig.

The opt-in `integration/access-projection.py` probe requires the same explicit kubeconfig and
REQUESTOR_ACCESS_TEST_RESULT output path, plus preloaded Core 0.33.4 and Python 3.13 Alpine
images. It uses synthetic tokens on a local unauthenticated route to isolate native kubelet
projection and Core reload; it does not establish user authentication or stream revocation.

The additional `REQUESTOR_ACCESS_COMPOSITE_RESULT` opt-in starts
`integration/access-composite.py` inside the native test's owned namespace. Preload the
`REQUESTOR_ACCESS_PG_IMAGE` PostgreSQL 16 image, Core and Python. It runs the real publisher
between initial and updated Core observations, uses PostgreSQL as the databroker backend,
restarts the database process and measures two logical target routes with distinct credentials.
It records new-request denial, sibling continuity and SSE/WebSocket lifetime with a candidate
300-second Core route timeout. A completed probe is not a passing stream gate: inspect
`streamBoundPassed` and `status` in its immutable result. Public synthetic routes do not qualify
human SSO, native Kubernetes upgrade protocols, Cloud SQL TLS/IAM or the full Helm controller.

The native API test also deletes the fixture identity, confirms issued-token invalidation,
rejects same-name/different-UID reenrollment and refuses a removed output. These are retirement
primitives, not an authenticated retirement receipt or automatic registry removal implementation.
