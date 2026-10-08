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

Stable gates still include real OAuth API/trust rotation, complete consumer/child/management
failure and revocation drills, capacity acceptance, natural-lifetime observation, monitoring
receiver, sole-writer adoption and paired public release verification. No stable acceptance report
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
