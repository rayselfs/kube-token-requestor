# Installation and upgrade

This is a management-cluster service. It does not install child identities, discover workloads,
change node pools or grant child RBAC. Installation and activation are separate operations.
No published release or production acceptance is implied by the source chart.

## Before installation

Use an accepted release-manifest matrix row. Verify the paired image/chart signatures and
checksums, the source commit and platform digest. Two schedulable management nodes are required
by hard Pod anti-affinity. Supply explicit API/broker/DNS egress and monitoring ingress rules;
NetworkPolicy enforcement must be verified on the operator's CNI.

Prepare an operator-owned registry from `examples/registry.json`, with actual API endpoints,
public CA hashes, cluster/SA/object UIDs and exact CA image digests. Keep credential payloads in
pre-existing mutable Opaque Secrets, never Helm values, command arguments or Git. Restrict access
and enable Kubernetes Secret encryption at rest. The chart owns no credential Secret.

For SecretIssuer, source keys are `ca.crt` and `token`; a long-lived source also requires the
`token-requestor.io/rotated-at` RFC3339 annotation. Output keys are `ca.crt` and `token`, with
`token-requestor.io/consumer` equal to the registered consumer ID. OAuth trust keys are `ca.crt`
(broker) and `api-ca.crt` (child); the client Secret key is `client-secret`. All references pin UID.

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
operator control. This controller never starts a CA that was already stopped before renewal.

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
