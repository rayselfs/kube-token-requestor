# Independent API capacity fixture

This is test code, not an API hosting product or a controller dependency. It uses a newly
named two-node kind management cluster, separate official API server Pods, independent etcd
prefixes and independent ServiceAccount signing keys. Every child must have a distinct actual
kube-system UID, separate from management. A shared in-memory fixture datastore does not turn
one Kubernetes API into twenty namespace aliases.

The opt-in profile creates three named consumers per child and runs actual upstream CA Pods
against independently issued tokenFile outputs. The CAPI fleet is empty and its management
identity is read-only: no node pools, VM provisioning or worker changes are exercised. All
consumers must rotate at least twice with unchanged Ready Pod UIDs, authenticated identity and
restricted permissions. One actual API is unavailable for five minutes; healthy peers must
keep publishing and the failed child must recover within the reviewed safety budget.

The capacity policy is accelerated at 1200 seconds, leaving enough credential margin for the
five-minute fault. It does not replace the separate old-token-expiry/TokenFile or natural
lifetime acceptance. A two-child smoke is explicitly not twenty-child acceptance. Only the
complete twenty-child profile emits capacity20Acceptance=true.

This fixture refuses workstation/remote Docker contexts: run only on a fresh Linux GitHub
Actions runner. The twenty-child profile requires at least 14 GiB of Docker memory; the smoke
requires 6 GiB. It does not modify Docker settings or allocate an external cluster. Cleanup
checks exact kind node IDs/labels and deletes only its generated cluster. All Helm/kubectl
commands use its explicit generated context and protected temporary bootstrap kubeconfig.

Private serving/signing keys remain in process memory or fixture API Secrets/projections.
Human bootstrap mTLS never becomes a controller identity. The controller gets only its named
issuer/output/state/Lease/lifecycle grants. Public CA pins and enrollment metadata are the only
values exported to Helm. API-server fixture containers receive NET_BIND_SERVICE for the
pinned official binary's file capability; this does not change the shipped controller security
context. Evidence exports only public synthetic version/count/result metadata.

The owner-dispatch workflow verifies public paired manifest/assets/image/chart signatures before
running this fixture. Native capacity acceptance currently targets amd64; it does not imply
arm64 at the same load. Normal Go tests validate PKI and compile the harness while the real API
profile remains opt-in. An unexecuted or failed profile is never accepted capacity evidence.

## Consumer failure profile

The separate owner-dispatched consumer-failure workflow uses a verified published paired
release and two independent synthetic child APIs with six actual CA processes. It removes
only the named affected CA scale patch grant, corrupts only that owned synthetic output,
and requires durable `StopUnconfirmed` while all five peers renew after the fault and retain
their ready Pod identities for at least 90 seconds. Restoring the exact grant must stop the
affected CA, publish a valid restricted replacement, and retain the operator safety latch;
it must not resume the CA automatically. Deployment and namespace UID guards remain active.

This profile is not capacity acceptance, natural token-lifetime acceptance, or actual VM
provisioning. It is pending until its sanitized receipt exists for the candidate source.
The default capacity profile and its requirement for every CA Pod to remain unchanged are
unaffected. Normal unit runs skip both opt-in live fixture profiles.
