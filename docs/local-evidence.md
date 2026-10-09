# Development acceptance evidence

Observed on 2026-10-08 UTC using task-owned synthetic kind clusters only. No operator/company
cluster, virtualization system or node pool was contacted or changed. These results precede
published release artifacts; release-manifest evidence must bind the exact released source.

| Check | Observed result | Limit |
| --- | --- | --- |
| Shared runtime | Two Ready replicas on separate management nodes; two children, three outputs | Development image, not a released support row |
| Real issuer/consumer APIs | Three distinct tokens; actual child identity/UID checks and allow/deny rights passed | Kubernetes 1.35.8 only |
| Actual CA startup | Upstream CA 1.35.2 with explicit entrypoint and complete read-only discovery grants | Empty CAPI fleet; no node provisioning |
| Accelerated TokenFile observation | 13 minutes, same Ready CA Pod/no restarts, repeated rotations, first token rejected after expiry, recent logs without forbidden/Unauthorized | 600-second tokens/early refresh; not natural 24-hour policy or 48-hour observation |
| Child API restart | Actual CA repopulated Node/CSI/resource caches and resumed scans after the local API restarted; no Unauthorized errors | Short reconnect only; prolonged outage drill remains open |
| Helm rolling upgrade | Latest development image reaches two Ready replicas; status/Lease UIDs unchanged; CA Pod retained | Uninstall/reinstall remains release smoke |
| Leader Pod loss | Lease holder changed within 35.5 seconds; status/Lease identities and CA Pod retained | Pod loss only; node/network partition drills remain open |
| Source security | Full race tests/vet/fuzz passed; govulncheck reports no vulnerabilities | Image CVE/SBOM/signature verification remains release workflow |
| Alert expressions | All eleven expressions parse; SafetyStop/StopUnconfirmed fixtures fire | Production receiver/on-call acceptance remains open |
| Local notification route | Rendered RequestorUnavailable rule scraped by real Prometheus 3.15.0 and Alertmanager 0.34.1; stopping/restoring the local shared controller delivered both firing and resolved notifications to a loopback receiver | Synthetic receiver only; CA Pod and nodes retained; other alert delivery profiles remain open |
| Issuer isolation/recovery | Expired only child-a's operator rotation annotation; after in-flight work drained, child-a output stayed unchanged while child-b rotated; restoring the source recovered child-a issuance | Development image, metadata rejection rather than child network partition; annotation restored |
| Consumer ownership conflict | Changed only the stopped second CA output's ownership annotation; that output stayed unchanged while its sibling rotated; annotation restored | Stopped consumer only; transport/RBAC denial and active-consumer failure remain separate drills |

Actual CA baseline index digest:
`sha256:aac369dc283927a623deb1af54696efcc722ae79255aa07788422e495bab887d`.
Kind node baseline index digest:
`sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0`.

The first observation attempt failed because its ten-second expiry rejection threshold did not
allow the API's validation tolerance. The corrected harness allows at most two minutes and still
requires observed rejection; it does not accept a token indefinitely or assume local claim parsing
proves API authentication. The complete corrected 13-minute run exited successfully.

Stable gates still include deployed OAuth projection/rotation, complete consumer/child/management
failure and revocation drills, capacity acceptance, natural-lifetime observation, all monitoring
receiver profiles and sole-writer adoption. The newer release and OAuth fixture evidence below
does not retroactively change these development results. No stable acceptance report
is fabricated from these partial development results.

## Released RC2 native API acceptance

Both native architectures passed the owner-dispatched [local API acceptance run](https://github.com/rayselfs/kube-token-requestor/actions/runs/37844705633).
Released source is `36a37434498a6f084f4c862509e1971ef6668a7e`; harness source is
`4b79bb12cfd6c29fc75fad57e80d63b2d6f723d4`. The signed public RC2 image/chart were verified and
pulled on fresh amd64/arm64 runners. Each run used two real child APIs, three distinct restricted
consumer tokens, upstream CA 1.35.2/Kubernetes 1.35.8, and the 13-minute accelerated TokenFile
observation plus issuer/consumer isolation drills. This is not OAuth, StopStart, provisioning,
natural-lifetime or stable support acceptance. Later permission/lifecycle hardening requires a
new release and new evidence rather than attributing it to RC2.

The local RC2 fixture also passed a real restricted issuer replacement/revocation drill: the
candidate issuer's actual child identity/effective rights were validated, the management source
was CAS-updated without changing UID, the predecessor child token Secret was UID/RV-deleted,
and the previous token was rejected by the real API. Both children rotated afterwards; the
active CA retained its Ready Pod UID. The adopted replacement remains restricted and was not
rolled back to the revoked predecessor. This is synthetic SecretIssuer recovery, not OAuth
revocation or operator-cluster acceptance.

## Released RC4 native API acceptance

The [released-image run](https://github.com/rayselfs/kube-token-requestor/actions/runs/37863931683)
completed successfully on both native amd64 and arm64. Controller and harness source are both
`cb84745db90a88c4430f4c15f6a6a4c50e81a00c`; version is `v0.1.0-rc.4`. Sanitized records are preserved
under `integration/evidence/rc4/`. Both used Kubernetes 1.35.8 and CA 1.35.2 with SecretIssuer.

Measured passing checks: three distinct restricted identities/effective grants; the same actual
CA Pod across two TokenFile rotations and predecessor rejection; isolated issuer/stopped-output
failures; two actual StopStart Pod replacements with manually suspended CA retained at zero;
restricted issuer replacement followed by real predecessor revocation. The actual CA image
index digest is the baseline above. No VM/node pool provisioning was involved. Accelerated
600-second lifetimes do not satisfy the natural-lifetime or >=48-hour gate.

## Real OAuth JWT API fixture

Exact source `0063978bac6d0cf752112e8c6ad4bd2d53d4651b` passed all push/PR checks, including native
amd64/arm64 [actual JWT API tests](https://github.com/rayselfs/kube-token-requestor/actions/runs/37865567132).
This source was merged by PR #20. The fixture verifies actual OIDC apiserver flags before exchange,
then authenticates the returned JWT against Kubernetes 1.35.8, checks named TokenRequest and
restricted effective rights, rejects wrong UID/CA trust, removes a JWKS predecessor, rotates the
client Secret with CAS and revokes the management subject SA UID. The already-issued CA token
remains independently valid after subject revocation.

This is a single synthetic API/provider fixture, not a deployed shared controller, kubelet
projected-volume rotation, actual CA reload through OAuth, vendor integration or stable support
matrix. The test broker is not part of the released controller. Earlier failed attempts are not
accepted evidence: the kubeadm v1beta4 patch was skipped by pinned kind for Kubernetes 1.35.8;
the corrected v1beta3 patch and effective-flag assertion passed fresh complete runs.

## RC5 complete native CA rerun

[Run 37871710423](https://github.com/rayselfs/kube-token-requestor/actions/runs/37871710423)
passed on native amd64 and arm64 using released source
`0fb65fa81125806190eeb8279179e5a6aff60601` and harness
`4894f6c2a8ee343be0b23341c215ca8721466ab5`. Sanitized receipts are
[amd64 receipt](../integration/evidence/rc5/amd64.json) and
[arm64 receipt](../integration/evidence/rc5/arm64.json).

This rerun verified actual named identity/RBAC, two TokenFile rotations in the same CA Pod with
predecessor rejection, consumer/issuer isolation, a five-minute actual child API partition,
two StopStart replacements with manual suspension retained, and issuer replacement/revocation.
The earlier failed RC5 run is not promoted: its observation timer cancelled the API context at
the final check. The fixed harness retains the 13-minute observation and acceptance requirements.

The policy remains accelerated (600 seconds), the CAPI fleet is empty, and no workers are
provisioned. These receipts prove neither natural lifetime, 20-child capacity, deployed OAuth,
receiver/on-call adoption nor complete production acceptance. RC6 distribution is independently
verified; its corresponding runtime reruns remain separate and pending.
