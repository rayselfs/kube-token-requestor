# Implementation plan

Status: M0 delivered; config, SecretIssuer, RFC 8693 exchange, TokenRequest, identity/rights checks and
output CAS, shared runtime and source chart are implemented. Local two-child/three-consumer
identity and restricted-RBAC acceptance passed. Full failure, OAuth API trust, delivery and
long-run acceptance remain pending; unit/protocol tests do not claim complete M1/M2 acceptance.
Each milestone is a small PR from latest origin/main in an isolated worktree.
No milestone authorizes a live cluster mutation or automatic production activation.

## Deliverables and code layout

```text
cmd/kube-token-requestor/          CLI: run, validate-config, version
internal/config/                  typed registry and semantic validation
internal/provider/                small issuer boundary and two providers
internal/issue/                   remote identity checks and TokenRequest
internal/reconcile/               queues, lifetime decisions, CAS and safety state
internal/status/                  sanitized durable status and restart intent
internal/observe/                 health, metrics and classified logging
charts/kube-token-requestor/       management-only Helm package
bootstrap/                        separate reviewed child identity/RBAC examples
integration/                      local multi-cluster and CA acceptance harness
.github/workflows/                validation, build, staged publication
```

Use Go standard HTTP/slog, client-go typed APIs/workqueue/leader election and focused OAuth/JWT
libraries when security correctness requires them. Pin dependencies/toolchains and verify
licenses. Do not hand-roll cryptography, create a plugin framework or add controller-runtime
unless a concrete need remains unmet by client-go. No CRD/webhook/database is needed.

## Milestones

| Milestone | Concrete result | Exit evidence |
| --- | --- | --- |
| M0 Specification | Contracts, operations, planned matrix, release gates | Document/example CI; owner reviews security tradeoffs |
| M1 Core | Typed config, issuer interface, SecretIssuer, TokenRequest, Secret CAS | Parser/fuzz, expiry/identity/redaction tests; real local RBAC denial |
| M2 OAuth | RFC 8693 provider with projected JWT and client_secret_basic | Conformance/error/rotation tests plus local JWT-auth API acceptance |
| M3 Shared service | HA election, fair queues, per-consumer retries, restart/safety state | Two children/three CAs; partition/crash tests and race detector |
| M4 Delivery | Hardened image, complete Helm chart, metrics/alerts/runbooks | Helm combinations, monitoring smoke and install/upgrade/uninstall tests |
| M5 Release candidate | Signed/digest-pinned image and OCI chart through GitHub | Release manifest/SBOM/checksums, OCI pull/install and negative promotion gates |
| M6 First real adoption | Candidate resources, sole-writer handoff and real CA evidence | >=48h, two natural rotations, old-token-expiry and rollback evidence |
| M7 Stable release | Accepted provider/version matrix and on-call readiness | All mandatory acceptance rows; production approval recorded |

M2 MUST produce working protocol implementation, not a stub. Test an exchange server which
validates projected subject identity and audience, and a real workload API that authenticates
the returned JWT and grants only named CA token creation. A mock-only test is marked protocol
coverage, not accepted product compatibility. Products are separate integrations; no product
must be selected to complete RFC-profile implementation.

## Acceptance matrix

Evidence is stored by release/commit with synthetic data. No real tokens/private inventory
belongs in this repository. Recorded production-adoption evidence may live in the operator's
private system; public matrix entries contain only sanitized result summaries and references.

| ID | Scenario | Required evidence |
| --- | --- | --- |
| A01 | Shared topology | One Deployment/two replicas, two local children and three independent CA outputs |
| A02 | Child outage | Healthy child rotates while failed child backs off within limits |
| A03 | Consumer failure | One output denied/conflicting; siblings and issuer acquisition remain serviceable |
| A04 | Lifetime | Real expiration, early refresh, short/unexpected TTL denied; expired CA rescued by valid issuer |
| A05 | RBAC | Exact named TokenRequest succeeds; other SA/namespace, Secrets, RBAC and CAPI writes denied |
| A06 | Identity/trust | Wrong UID, SA, audience, privileged groups, CA and endpoint cause no publication |
| A07 | Concurrency | Two-leader overlap/foreign writer, CAS conflicts, no older-expiry rollback |
| A08 | Crash durability | Crash before/after publication and between consumers resumes without corrupting healthy outputs |
| A09 | HA | Leader/node loss and shutdown; stale worker cancellation; failover within accepted lease budget |
| A10 | TokenFile | Same actual CA Pod through two real rotations and old-token expiry; authenticated API scans |
| A11 | StopStart | Persisted operation resumes safely; stopped/manual-suspended CA not auto-started |
| A12 | Bootstrap | Issuer revoked/replaced; OAuth subject/client/broker trust revoked; approved targeted recovery |
| A13 | Management/time/rate | StopUnconfirmed, skew/jumps, 429 Retry-After and bounded retries; no hot loops |
| A14 | Config lifecycle | Duplicate/unknown fields, unsafe refs, reload/removal; no stale adoption or lost safety guard |
| A15 | Exposure | Canary material absent from logs/errors/status/metrics/artifacts/process arguments |
| A16 | Capacity | 20 local children x 3 CAs; four workers; 5m outage/burst recovery within safety budget |
| A17 | Handoff | Exactly one writer, CA policy unchanged, all worker/CP identities retained, rollback drill |
| A18 | Long run | >=48h and >=2 natural CA rotations; failure and revocation drills separately recorded |
| A19 | OAuth protocol | RFC profile, scope/audience/subject, basic-auth target isolation, invalid responses and cancellation |
| A20 | OAuth Kubernetes trust | Real API JWT authentication/RBAC, JWKS/client-secret/subject-token rotation and denied exchange |
| A21 | Helm lifecycle | Monitoring on/off, empty/mixed targets, named RBAC, replicas 0/2, runtime state preserved on upgrade |
| A22 | Monitoring | Missing leader, expiry/failure/stop alerts reach owner; no secrets; recovery clears appropriate alerts |
| A23 | Release | Image/chart/version/digest consistency, signatures/provenance, install from GHCR and rollback |
| A24 | Installation guard | Unsupported API/schema/provider fails before write; independent human/workload credentials |

Use fake clock and fake transports for decision tests; real local API servers/clusters for RBAC,
TokenRequest/JWT authentication/Lease semantics. Kubernetes fake clients do not enforce these.
Use isolated local clusters for multi-child and revoked-credential tests. Real CA tokenFile behavior
needs actual accepted image and filesystem projection; do not extrapolate from client-go alone.

## CI and security checks

Each implementation PR runs `go test -race ./...`, go vet, parser fuzz seeds, config/example
validation, targeted integration tests, govulncheck and license/security scanning. Helm changes
run lint/template, schema checks and install/upgrade fixtures. Image changes add vulnerability
scan, nonroot/read-only startup, architecture checks and SBOM generation. Pin third-party Actions
by commit SHA. PR workflows never have package-write, production credentials or live kubeconfigs.
Avoid pull_request_target execution of untrusted code and secret-bearing HTTP debug logs.

Go, client-go, Kubernetes, CA, Helm and scanner versions are pinned when implementation starts;
unknown targets are not implied by a planned matrix. No tests may reach arbitrary remote clusters.

## Safe adoption sequence

1. Operator verifies management/child UIDs, CA trust, versions, RBAC, Secret storage encryption,
   network path, issuer owner, monitoring receiver and absence of competing writers.
2. Review exact child bootstrap and management Helm/IAM changes. Child bootstrap is applied
   separately after approval, with least privilege and secure credential transport.
3. Install management chart with replicas 0 and disabled targets; preserve existing CA/updater.
4. Create independent candidate outputs; approve activation of controller replicas 2 and candidate
   issuance tests. Candidates MUST NOT point at an active CA until handoff is approved.
5. Confirm candidate RBAC/rotation/failure evidence. Suspend old writer, wait for active Jobs to
   terminate, verify no external Secret sync/writer, then transfer named outputs by exact UID.
6. Approve CA consumer mount/activation if needed. Start with StopStart compatibility; enable
   TokenFile only after A10. Never run both writers and never change worker counts.
7. Complete long-run, monitoring, recovery and release acceptance before stable activation claim.

Rollback stops shared issuance, drains workers and preserves latest valid output and all nodes.
Restore previous updater only after verifying pinned UIDs, credential format and its issuer
requirements; long-lived issuer compatibility MUST NOT be assumed. Rebootstrap old short-lived
issuer if needed, then obtain separate approval to resume CA. Never run two credential writers.

## Definition of done

M0 is complete when the generic spec, plan, monitoring/release contracts and example are pushed
and their CI passes. It does not mean controller/chart/image completion.
M7 requires all applicable acceptance rows, approved matrix/owner, artifact verification and
operating alert/recovery evidence. A release with unaccepted OAuth product integration explicitly
limits its support to the accepted profile/fixtures; it never advertises arbitrary OIDC support.
