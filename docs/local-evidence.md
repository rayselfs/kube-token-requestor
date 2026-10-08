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
| Alert expressions | All eleven expressions parse; SafetyStop/StopUnconfirmed fixtures fire | Real receiver delivery and recovery not accepted |

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
