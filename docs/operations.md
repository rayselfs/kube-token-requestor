# Monitoring and operations contract

Status: metrics, health endpoints and optional chart alert rules are implemented. Operator
receiver/on-call acceptance and stable-release evidence remain required.

## Metrics

Internal HTTP metrics, no public ingress by default. Use bounded labels from registry IDs;
never bearer material, decoded JWTs, response bodies, exception messages or Secret contents.

| Metric | Type | Labels / meaning |
| --- | --- | --- |
| kube_token_requestor_leader | Gauge | instance; 1 active leader, 0 standby |
| kube_token_requestor_config_valid | Gauge | current snapshot accepted |
| kube_token_requestor_reconcile_total | Counter | cluster, result; sanitized fixed result set |
| kube_token_requestor_reconcile_duration_seconds | Histogram | cluster; bounded buckets |
| kube_token_requestor_token_request_total | Counter | cluster, consumer, result |
| kube_token_requestor_exchange_total | Counter | cluster, result |
| kube_token_requestor_secret_conflicts_total | Counter | cluster, consumer |
| kube_token_requestor_token_expiry_timestamp_seconds | Gauge | cluster, consumer; actual CA expiry |
| kube_token_requestor_last_success_timestamp_seconds | Gauge | cluster, consumer |
| kube_token_requestor_issuer_rotation_due_timestamp_seconds | Gauge | cluster; SecretIssuer policy |
| kube_token_requestor_issuer_expiry_timestamp_seconds | Gauge | cluster; ONLY finite issuer credentials |
| kube_token_requestor_condition | Gauge | cluster, consumer, fixed condition; 1 active |
| kube_token_requestor_queue_depth | Gauge | bounded shared work backlog |
| kube_token_requestor_leadership_changes_total | Counter | process-local leadership transitions |
| kube_token_requestor_registry_targets | Gauge | number of accepted enabled consumers |

Never represent non-expiring issuer expiry as zero or infinity. Export its rotation-policy due
time separately. Expiry/condition/reconcile metrics are leader-only; standby exports process and
leadership/health metrics. Queries join/filter active leader and detect missing samples; no-data
is not success. Cardinality is bounded by validated enrollment and fixed result/condition enums.
Condition labels do not expose arbitrary error text; remove series for offboarded targets.

Named status ConfigMap contains accepted config hash/generation, timestamps, expiry, UID/RV,
classified conditions and StopStart intent. Secrets remain credential truth. Status writes are
serialized/CAS; status failure prevents persisting unsafe restart intent. It never contains JWTs.

Health endpoints: liveness event-loop progress; readiness validated config + management API +
functioning election. Standby Ready does not mean leader. One child outage never makes all Pods
unready or creates restart storms. Bind metrics/health to configured internal interfaces; no pprof
or token/registry dump endpoints in production. Monitor readiness and leadership independently.

## Alert contract

Chart supplies optional PrometheusRule. Concrete queries are implemented and promtool-tested
with absent-series, failover, clock and stale-metrics fixtures before release.

| Alert | Initial threshold | Required response |
| --- | --- | --- |
| RequestorUnavailable | No ready replicas OR absent leader telemetry >2m | Restore shared service; assess all token budgets |
| MultipleLeaders | >1 reported leaders beyond lease allowance | Investigate partition; verify CAS/lifetime consistency |
| ConfigRejected | Invalid latest snapshot >2m | Fix/revert registry; verify expiry protection |
| ConsumerRenewalFailed | Classified failures persist >10m while due | Check target API/RBAC/provider and output writer |
| ConsumerExpiryWarning | <2h remaining without recent successful rotation | Page owning team before stop deadline |
| ConsumerSafetyStop | Latched expiry/identity stop | Validate replacement; explicit acknowledgement to resume |
| StopUnconfirmed | Any stop cannot be confirmed | Urgent manual check of exact CA; preserve workers |
| BootstrapRequired | Issuer/client authentication revoked/invalid | Rebootstrap only affected enrollment |
| IssuerRotationDue | Long-lived issuer rotation due in <7d or overdue | Rotate with secure CAS and revoke predecessor |
| OAuthDependencyFailure | Due exchange cannot authenticate >10m | Check broker/client/subject trust; no token fallback |
| StaleOrMissingTarget | Registry has enabled target without fresh target telemetry | Restore observation; never treat as empty healthy set |

Alerts route to an installation-specific approved receiver/on-call owner. Credentials for that
receiver are never chart values or repository content. ServiceMonitor/PrometheusRule generation
alone is not acceptance: force each essential failure, confirm receiver delivery, investigate via
runbook and confirm recovery/latched-stop behavior. Metrics scrape path must be access-controlled.

## Ownership and runbooks

Every enrollment MUST identify an owning team in the operator's inventory, issuer rotation owner,
bootstrap approver and alert receiver. Release owner maintains compatibility and security policy.
Company-specific names/escalation paths are external to this repository.

### Routine issuer rotation (SecretIssuer)

1. Confirm target UID, issuer SA and narrow grants, no simultaneous rotations/config changes.
2. Through approved bootstrap channel, create replacement restricted credential. Keep payload
   off workstation/workspace/logs. Validate its identity/rights and API trust.
3. CAS update exact issuer Secret, preserve UID; record non-secret rotation generation/time.
4. Confirm next reconciliation acquires replacement and CA outputs rotate successfully.
5. Revoke predecessor and prove it can no longer authenticate; verify healthy siblings.
6. Record next policy due date. Updating a Secret does not revoke the old credential.

Long-lived SA token issuance/removal is an operator lifecycle. Deleting the underlying token
Secret or identity/permissions may revoke it; validate behavior on the accepted Kubernetes version.
Never remove the shared CA identities or unrelated role bindings as cleanup.

### OAuth dependency recovery

Check broker availability and certificate trust, projected JWT audience/issuer/key trust, exact
client Secret UID and rotated client authentication, expected API JWT mapping and issuer grants.
Classify exchange failure separately from API rejection. Repair the approved dependency, validate
a candidate and acknowledge only affected safety-stopped consumers. No automatic provider fallback.
Human SSO success does not prove the machine Token Exchange profile is operational.

### Expiry, emergency stop and resume

Keep CA running during safe transient failure. At safety deadline, controller attempts guarded
stop of that CA only. StopUnconfirmed requires on-call intervention. If the requestor itself is
unavailable, monitoring/on-call enforces this procedure; HA is not a substitute for it.
After restoring credentials, validate actual expiry, identity, child UID and permissions, then
explicitly acknowledge the latched stop in reviewed configuration. Never resume every CA globally.
Workers and control planes remain untouched; no default replica reset.

### Provider migration

Create new provider credentials/config separately; validate exchange/API rights against candidate
outputs. Suspend target and drain work, review exact config generation change, switch provider,
revalidate and resume. Keep old provider configuration available only for an approved rollback;
never retry a failed exchange through the old provider automatically. Revoke old issuer after
replacement acceptance. Healthy clusters keep their independent provider and output state.

### Service outage / rollback

Check remaining lifetimes, current writer/leadership and affected enrollments. Restore controller
or previous accepted image/chart only if registry/status semantics and credential formats remain
compatible. Secrets outlive Helm lifecycle. Drain the old writer before enabling another one.
Use the release manifest's downgrade restrictions; if incompatible, pause and repair instead of
silently falling back to admin credentials or resetting workers.

## Acceptance

Require receiver-delivered failure/recovery tests, standby/missing-leader tests, long-lived issuer
rotation/revocation drill, OAuth trust/client-secret rotation, stale/missing telemetry, stop-not-
confirmed behavior and >=48h observation. No secrets may appear in captured telemetry/evidence.
