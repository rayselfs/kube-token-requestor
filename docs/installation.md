# Installation and upgrade

This is a management-cluster service. It does not install child identities, discover workloads,
change node pools or grant child RBAC. Installation and activation are separate operations.
Published candidates are experimental; a public package does not imply production acceptance.
Check [release evidence and limitations](releases.md) before selecting a version.

Review the separate [child bootstrap example](../bootstrap/README.md) for exact issuer/consumer
rights and secure credential preparation. It is not applied by Helm or the controller.

## Before installation

Use an accepted release-manifest matrix row. Verify the paired image/chart signatures and
checksums, the source commit and platform digest. Two schedulable management nodes are required
by hard Pod anti-affinity. Supply explicit API/broker/DNS egress and monitoring ingress rules;
NetworkPolicy enforcement must be verified on the operator's CNI.

For experimental acceptance, use the selected candidate's signed manifest and documented limits
instead of claiming an accepted production row. Resolve image/chart digests from that manifest;
do not copy a predecessor's digest from an old example. RC2 is superseded for new testing.
Download the release's signed manifest/bundle and chart package. With pinned cosign v3.1.3:

```sh
identity='https://github.com/rayselfs/kube-token-requestor/.github/workflows/release.yml@refs/heads/main'
cosign verify-blob --bundle manifest.sigstore.json \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com release-manifest.json
```

Check the package SHA256 against the signed manifest's `chart.packageSHA256`, not an unsigned
checksum file alone. Review signatures on the manifest's image/chart digest references as well.
Native public pulls and stopped-default installation are covered by the release smoke; child
authentication and operating-policy acceptance remain separate.

Prepare an operator-owned registry from `examples/registry.json`, with actual API endpoints,
public CA hashes, cluster/SA/object UIDs and exact CA image digests. Keep credential payloads in
pre-existing mutable Opaque Secrets, never Helm values, command arguments or Git. Restrict access
and enable Kubernetes Secret encryption at rest. The chart owns no credential Secret.

The workload API must support a complete SelfSubjectRulesReview for the enrolled identity
namespace. Effective resource grants (including cluster bindings) are checked against the issuer
or scheduling-read/events profile; wildcard access, credential reads and unrelated writes are
rejected. Standard public discovery/JWKS GET grants are allowed. An incomplete/erroring authorizer
fails closed. Review additional bindings in other namespaces independently: this review cannot
enumerate arbitrary external RoleBindings and does not replace an operator RBAC audit.

For SecretIssuer, source keys are `ca.crt` and `token`; a long-lived source also requires the
`token-requestor.io/rotated-at` RFC3339 annotation. Output keys are `ca.crt` and `token`, with
`token-requestor.io/consumer` equal to the registered consumer ID. OAuth trust keys are `ca.crt`
(broker) and `api-ca.crt` (child); the client Secret key is `client-secret`. All references pin UID.

Lifetime/audience/provider/reload-policy changes require both old/new targets disabled and the
affected CAs drained. Stop the requestor and wait for all its Pods to disappear before changing
these fields; the shared status generation does not prove that every HA replica accepted an
intermediate disabled configuration. Restart the requestor with disabled targets, validate the
new policy, then separately enable exact targets. A persisted restart intent from another
generation or policy is cancelled with a latched safety stop; validate the replacement and issue
a fresh acknowledgement before an explicit operator start. Runtime checks the live registry/status generation and Lease holder before issuance,
publication and resume; output/status CAS remains necessary because cross-object fencing is not
atomic. Safety guards still operate when a new registry is invalid.

Confirm the registry namespace matches each CA Secret mount namespace. CA tokens must use a
normal read-only Secret volume without `subPath` or environment-variable copies. Use StopStart
until the exact CA image's TokenFile reload behavior has passed actual-Pod acceptance.

## Stopped installation

Pull the accepted OCI chart by its manifest reference/digest into a protected task directory.
Review the rendered chart and RBAC against the enrollment registry. Install with `replicaCount: 0`
and targets explicitly disabled. No API credential acquisition occurs while replicas are zero.
Check rendered objects, namespaced named-resource grants, runtime status/Lease UIDs and ownership.
An empty registry is valid. The default values intentionally provide no usable image digest or
cluster UID; activating those defaults must fail.

After approved candidate issuance and sole-writer handoff, activate `replicaCount: 2` with the
released image digest and separately enable exact targets. Ensure CA desired counts remain under
operator control. This controller never starts a CA that was already stopped before renewal. For an operator
suspension, disable the consumer and confirm its accepted generation before scaling the CA to
zero; a scale-to-zero alone during an owned restart is ambiguous after transport/crash recovery.
A known competing Scale CAS conflict cancels restart authority with a latched safety stop.

## Monitoring

Provide Prometheus Operator ServiceMonitor/PrometheusRule CRDs before enabling the optional chart
objects. Labels must match the operator's selection policy. ServiceMonitor uses the Helm release
name as its job label. Route alerts to an operating receiver and exercise failure/recovery delivery.
A successful rule syntax test is not notification delivery acceptance.

`/livez` fails if the registry control loop has made no progress for two minutes. `/readyz` requires
an accepted registry and reachable pinned management Lease. Standbys expose base metrics only;
target state is emitted by the elected leader. Alert on missing/stale targets and absent leaders.

## Upgrade, stop and uninstall

Keep the same release name/namespace, pre-existing source/output Secrets and object UIDs.
Perform a dry-run/render review before upgrade; verify preserved status/Lease identities and
restart intent afterwards. Rolling updates use zero surge and at most one unavailable replica.
Unsupported downgrade is a stop-and-review boundary, not an automatic rollback.

Stop issuance by setting controller replicas to zero and wait for both Pods to terminate. Keep
all workers and current credentials. Consumers eventually reach credential expiration: choose
an approved alternate writer or stop the named CA before expiration. Never run two writers.

Helm intentionally keeps runtime status and Lease on uninstall. External credential Secrets,
CA Deployments and child identities are never chart-owned. A reinstall with the same name must
review retained runtime state; delete it only through a separate, explicit operator decision.
A safety stop is latched: validate replacement credentials, annotate only the affected CA with a
fresh UUID `token-requestor.io/acknowledge-stop`, then explicitly resume after the latch clears.
