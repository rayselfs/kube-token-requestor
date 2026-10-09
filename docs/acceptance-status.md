# Acceptance evidence ledger

Snapshot: 2026-10-09. Pending rows are not automatically updated by running CI.

This is a coverage index, not owner-approved production acceptance. The published candidate is
RC6, source `7884c8a6738692666ccc8c13c132c88f2c62aca5`. Receipts preserve controller source and
actual harness commit separately. Tests added after that source require a fresh candidate before
exact-source stable promotion. No measured 48-hour natural observation is currently available.

The [mandatory matrix](implementation-plan.md#acceptance-matrix) defines the requirements.
`Partial` means useful evidence exists but the complete scenario has not been accepted.
`Runtime` identifies an actual API/controller/CA test; it does not imply real operator adoption.
Fake-client and loopback protocol tests remain distinguishable from real Kubernetes RBAC enforcement.

| ID | Current coverage | Evidence and remaining boundary |
| --- | --- | --- |
| A01 | Runtime | RC6 two-child/three-output [CA receipt](../integration/evidence/rc6/ca-amd64.json); one CA active, other consumers stopped in this profile. |
| A02 | Runtime | RC6 five-minute actual child API partition and healthy sibling rotation; [CA receipts](local-evidence.md). |
| A03 | Partial | Actual stopped-consumer ownership conflict/issuer isolation in CA receipts; [output CAS tests](../internal/publish/publish_test.go). Full active-consumer denial drill remains separate. |
| A04 | Partial | Actual two rotations and old-token expiry in CA receipts; [TTL/claim tests](../internal/credential/credential_test.go) and [invalid TokenRequest tests](../internal/issue/issue_test.go). Unexpected TTL/clock fault coverage is not a deployed fault matrix. |
| A05 | Runtime | Real issuer/consumer identity and effective restricted RBAC in CA receipts; [effective-permission contract](../internal/issue/review_test.go). |
| A06 | Partial | Real OAuth JWT API trust fixture plus [trust tests](../internal/provider/trust_test.go) and [identity tests](../internal/issue/issue_test.go). All deployed wrong-identity/trust combinations are not yet accepted. |
| A07 | Partial | [Pinned Lease tests](../internal/controller/lease_test.go), [live-publication pins](../internal/controller/current_test.go), [CAS tests](../internal/publish/publish_test.go) and foreign-writer runtime isolation; real overlapping-leader drill remains separate. |
| A08 | Partial | [Durable lifecycle tests](../internal/reconcile/lifecycle_test.go) cover stale leader/generation, stop/restart intent and conflicts. Instruction-level deployed crash injection is not claimed. |
| A09 | Pending runtime | Two ready native controller replicas are observed; actual leader-loss/Lease failover profile is under review in PR #36. Node-loss coverage is separate. |
| A10 | Runtime | Both native RC6 CA receipts: same actual CA Pod, two real rotations, old token rejected and API scans. Accelerated 600-second policy is not natural-lifetime observation. |
| A11 | Runtime | RC6 actual StopStart replacements and manually suspended CA retention in CA receipts; [lifecycle tests](../internal/reconcile/lifecycle_test.go). |
| A12 | Partial | RC6 restricted issuer replacement/predecessor revocation and actual projected-subject rejection/recovery in [OAuth receipt](../integration/evidence/rc6/oauth-amd64.json). Every client/broker trust revocation combination is not yet accepted. |
| A13 | Partial | [Retry-After/safety tests](../internal/reconcile/throttle_test.go), [scale tests](../internal/reconcile/scale_test.go), lifetime tests. Real management outage and time-jump fault matrix remain separate. |
| A14 | Partial | [Parser tests](../internal/config/config_test.go), [registry rebind guards](../internal/controller/transition_test.go), [startup CAS retries](../internal/controller/reload_test.go). Full deployed reload/removal matrix remains separate. |
| A15 | Partial | [Sanitized observation tests](../internal/observe/observe_test.go) and provider tests; runtime receipts contain only public status. A complete runtime canary exposure sweep is not claimed. |
| A16 | Pending full capacity | Two independent APIs/six actual unchanged CAs passed [smoke run 37878557813](https://github.com/rayselfs/kube-token-requestor/actions/runs/37878557813). Twenty-API/sixty-CA [run 37879854148](https://github.com/rayselfs/kube-token-requestor/actions/runs/37879854148) is pending. Both use separate stores/signers/identities; smoke is not full acceptance. |
| A17 | Pending adoption | [Safe adoption sequence](implementation-plan.md#safe-adoption-sequence) specifies sole-writer transfer and preservation of workers. Synthetic empty CAPI fixtures do not prove an operator's worker-pool handoff. |
| A18 | Pending | [Guarded natural-policy harness](../integration/local/natural.go) exists; no uninterrupted 48-hour observation has started or passed. Accelerated runs never substitute. |
| A19 | Protocol covered | [OAuth provider tests](../internal/provider/provider_test.go) and [broker fixture](../integration/oidc/broker_test.go). Support is the documented RFC profile, not arbitrary OIDC/vendor compatibility. |
| A20 | Runtime, limited topology | Both RC6 [OAuth receipts](local-evidence.md) show actual API trust, kubelet projection rotation and rejection recovery with unchanged source Secret/leader/Pods. Co-located synthetic API topology; no actual CA process or vendor product in this OAuth profile. |
| A21 | Partial | [Chart matrix](../integration/chart/chart_test.go), RC6 install/upgrade fixtures and retained runtime state. Complete uninstall/reinstall lifecycle acceptance remains separate. |
| A22 | Partial | All eleven [rendered alert firing/recovery profiles](../integration/chart/alert_profiles_test.go) and [actual Alertmanager firing/resolved deliveries](../integration/chart/receiver_test.go). Live scrape chain and installation-specific on-call acceptance remain separate. |
| A23 | Candidate runtime | [Paired RC6 release](https://github.com/rayselfs/kube-token-requestor/releases/tag/v0.1.0-rc.6), signatures, manifest/checksums/SBOM, native install and guarded recovery. Stable promotion report remains absent. |
| A24 | Partial | [Config/API installation guards](../internal/config/config_test.go), [bootstrap grants](../integration/bootstrap_test.go), runtime restricted identities. Full unsupported-target deployment matrix is not claimed. |

## Promotion boundary

Before recording [stable acceptance](acceptance-report.md), close the remaining applicable
scenario gaps, publish and verify a final candidate, bind fresh receipts to its exact source,
freeze that source during uninterrupted natural observation, and obtain explicit owner review
of compatibility, failure/recovery, receiver delivery and operator adoption evidence.

An installation can review and stage RC6 with controller replicas zero using the
[installation guide](installation.md). Staging is not activation or production acceptance.
No repository CI or release authorizes changes to an external Kubernetes cluster.
