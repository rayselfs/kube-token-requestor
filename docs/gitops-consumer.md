# GitOps credential publication (unreleased)

This explicit consumer profile reuses requestor issuer acquisition/renewal, TokenRequest,
leadership/generation guards and CAS publication. It adds no issuer service, Vault dependency,
application sync, deployment scaling, cluster discovery or resource adoption.
[The synthetic example](../examples/gitops-registry.json) is disabled by default.

## Bounded authority

`gitops-configmap` supports a single identity namespace and a named ConfigMap mutation target.
Consumer permissions are ConfigMap get/list/watch, update/patch on only the named object,
get of its own ServiceAccount, get of the pinned kube-system Namespace, and Kubernetes default
self-review/discovery. It has no create/delete, Secret access, impersonation, token minting or
RBAC authority. The identity reads are explicit additional requirements, not permission to
reuse an existing Access profile. Effective-rule review covers the enrolled namespace and
cluster bindings; separately audit bindings in other namespaces.

The issuer retains exact named TokenRequest grants. It additionally needs GET on only the
pinned bound Secret; it cannot create, delete or modify that Secret. Requestor reads its UID,
requests a Secret-bound token, checks the returned binding and authenticates the token against
the destination. Changing/deleting the bound Secret does not trigger automatic recreation or
re-enrollment. A compromised renewable issuer can mint successor credentials until its authority
is revoked; consumer lease deletion alone does not revoke the issuer. Incident response must
stop/revoke issuer authority as well as account for already-issued consumers.

## Output and ownership

`reloadPolicy: ArgoSecret` selects a pre-existing UID-pinned Opaque Argo cluster Secret, with
exactly `name`, `server`, `namespaces`, `clusterResources`, `project`, and `config` data keys.
The registry pins name, project, namespace, endpoint/CA and enrollment UID. The Secret must have
`argocd.argoproj.io/secret-type: cluster`, `token-requestor.io/consumer` and
`token-requestor.io/enrollment-uid` annotations identifying the approved enrollment.
`clusterResources` must be `false`. The config accepts only bearerToken and tlsClientConfig
with explicit insecure=false and caData; duplicate/unknown auth fields are rejected.

Publication replaces only data/config (retaining trust and changing its bearer token) and
renewal metadata, with UID/resourceVersion tests and authenticated successor readback.
Destination metadata, labels, other annotations and data bindings are retained. Argo must
independently demonstrate reload and comparison; CredentialPublished is not Synced or Ready.

Before activation, the operator must stop the previous Secret writer through its source of
truth and prove it no longer writes. An ESO target Retain policy alone is not a writer fence.
Never run ESO and requestor as concurrent writers. No automatic output creation/deletion or
ownership takeover exists. Rollback reverses writer ownership and supplies a valid current
credential; restoring an expired value is not recovery.

## Failure and retirement

An invalid/unsafe output latches GitOpsBlocked; disabled enrollment reports GitOpsDisabled.
No workload is scaled. Recovery requires an independently bootstrapped valid credential and a
new acknowledgement UUID under the existing credential-only recovery contract. Operators must
contain Argo operations during credential incidents; stopping publication does not revoke a
still-valid token or an in-flight request. No Argo admin login or SSO credential is used here.

Hot rebinding/removal is rejected, like other consumers whose external retirement cannot be
proved by requestor. Use an isolated GitOps release and an operator-reviewed stop/retirement
procedure, not an Access or autoscaler instance. Preserve output identity during handover.

## Validation and release boundary

Run Go race/unit/integration, vet, specification, Helm and security checks. The optional
TestGitOpsNativeAPI requires REQUESTOR_GITOPS_TEST_KUBECONFIG pointing only to the explicitly
named loopback kind fixture in that test. It qualifies real API issuance, RBAC, CAS and bound
Secret revocation; it does not qualify a deployed controller, two-cluster transport, Argo reload,
issuer-renewal scheduling, company SSO or production acceptance. Never pass a company kubeconfig.
A paired immutable release and a separately reviewed installation are still required.

The Go CI job also provisions the isolated kind fixture and runs the native API contract.
Recovery tests require a fresh acknowledgement and a newer valid credential, rejecting reused
acknowledgements and older replacements. The rendered GitOpsBlocked alert is tested with
promtool through firing and recovery; a live alert receiver remains an installation gate.
