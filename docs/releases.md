# GitHub release and compatibility contract

Status: `v0.1.0-rc.6` is published with public signed image/chart and native platform/Helm smoke.
The support status is experimental; its accepted production matrix remains empty.

RC6 binds source `7884c8a6738692666ccc8c13c132c88f2c62aca5`. Its complete
[paired release workflow](https://github.com/rayselfs/kube-token-requestor/actions/runs/37872614541)
passed native amd64/arm64 anonymous pulls, signatures, startup, full license-text comparison and
retained-state Helm installation, upgrade, uninstall and reinstall. All release checksums and the
manifest/image/chart signatures were independently verified locally against the exact workflow
identity. The image index is `sha256:14250ee246c76f102691b2ca354d485cae729c67f029a4f2320093d2972226ed`;
the chart OCI digest is `sha256:29ef5ea8c364a02c759422eaa8b9cf53cb244d430b6815043a40a53e5ad53957`.
Always use the signed manifest to obtain the complete platform/package pins.

RC6 includes strict public-CA parsing, bounded HA startup status-conflict retries and OAuth
recovery when a rejected projected subject is replaced by kubelet. Regression tests cover those
fixes. Both released-image runtime reruns subsequently passed on native amd64 and arm64:
[full CA/partition/recovery](https://github.com/rayselfs/kube-token-requestor/actions/runs/37873398641)
and [deployed OAuth projection/recovery](https://github.com/rayselfs/kube-token-requestor/actions/runs/37873644034).
OAuth recovery retained the same leader/two Ready Pods and source Secret identities/versions.
The CA receipt includes actual old-token rejection, the five-minute API outage, StopStart/manual
suspension and issuer recovery. Distribution smoke alone does not prove these behaviors. Earlier release bytes and evidence remain immutable. RC6 supersedes
RC2/RC4/RC5 for new acceptance testing; no natural-lifetime, capacity or operator-adoption gate
has been declared passed.

RC4 binds source `cb84745db90a88c4430f4c15f6a6a4c50e81a00c`. The complete
[paired release workflow](https://github.com/rayselfs/kube-token-requestor/actions/runs/37862977110)
passed on native amd64/arm64: anonymous pull, signatures, hardened startup, complete license-text
comparison and retained-state Helm install/upgrade/uninstall/reinstall on synthetic Kubernetes
1.35.8. Image, chart and manifest signatures were also independently verified locally against
the exact release workflow identity. These distribution smokes use an empty fleet and do not
constitute provider/CA compatibility or production acceptance. The separate released-image
[multi-child CA acceptance run](https://github.com/rayselfs/kube-token-requestor/actions/runs/37863931683)
passed on both native architectures. It verified three distinct consumer identities, two actual CA
TokenFile rotations with predecessor rejection, issuer/consumer isolation, two StopStart Pod
replacements with manual suspension retained, and issuer replacement/revocation. Tokens used an
accelerated 600-second policy and the CAPI fleet was empty: this proves neither natural-lifetime
acceptance nor node provisioning. Full failure/capacity/monitoring/adoption gates remain open.

RC2 is superseded for new acceptance testing. Its original artifacts/evidence below remain
immutable; later candidates include lifecycle/RBAC hardening and HTTP dependency security fixes.

RC2 binds source `36a37434498a6f084f4c862509e1971ef6668a7e`. Both native platforms passed anonymous
pulls, signature verification, startup and retained-state Helm install/upgrade/uninstall/reinstall
on synthetic Kubernetes 1.35.8. The publisher's wildcard artifact selection failed afterwards;
publication was completed from the same original verified assets, without rebuilding/overwriting
OCI bytes. [Release notes](https://github.com/rayselfs/kube-token-requestor/releases/tag/v0.1.0-rc.2)
record that limit. The workflow correction selects only release assets and platform smoke records.

## Artifact locations

| Artifact | Destination |
| --- | --- |
| Source / release notes / evidence | github.com/rayselfs/kube-token-requestor |
| OCI controller image | ghcr.io/rayselfs/kube-token-requestor |
| OCI Helm chart | ghcr.io/rayselfs/charts/kube-token-requestor |
| Chart package / checksums / SBOM / manifest | GitHub Release assets |

New releases include `licenses.csv` and `licenses.tgz`: the inventory and complete dependency
license/notice files collected for both Linux architectures, plus the project Apache-2.0 text,
project notice and Go runtime license. The identical tree is shipped at `/licenses` in each
controller image. The packaged chart includes the project LICENSE and NOTICE. Native release
smoke compares image texts with the signed/checksummed bundle and verifies chart texts; a
license inventory alone is insufficient. This packaging change does not alter existing RC2 bytes.

The chart basename and Chart.yaml name are `kube-token-requestor`. Helm pushes the package to
`oci://ghcr.io/rayselfs/charts`; clients install the chart reference with the basename appended.
GHCR hosts both image and chart; no external chart registry, Pages or Docker Hub is required.
Private source/package pulls need operator-supplied registry authentication; package visibility
is an explicit owner choice and may not automatically follow source visibility.

## Version policy

Controller SemVer `vX.Y.Z`; initial chart version `X.Y.Z`, appVersion `X.Y.Z` in lockstep. Config
schemaVersion is separately tracked; breaking schema change requires explicit migration and a
major controller version once stable. Pre-1.0 releases are explicitly preproduction/prerelease
until complete evidence supports stated production use. Chart and image tags are immutable;
Helm values use the released image digest rather than `latest` or a floating tag.

A release MUST pair source commit, image/index/platform digests, chart digest and matrix evidence.
Chart-only fixes still create a paired release and rerun compatibility; do not silently retag
an old artifact. Schema/status changes define upgrade and downgrade behavior before publishing.

## Candidate compatibility matrix

These rows are test targets, NOT support claims. Select/pin concrete toolchains and CA images
when implementation begins. Unknown/disallowed versions MUST fail enrollment before writes.

| Controller / chart | Management Kubernetes | Child Kubernetes | CA | Provider | Evidence / status |
| --- | --- | --- | --- | --- | --- |
| Unreleased | local 1.34 | local 1.34 / 1.35 | exact digest pending | SecretIssuer | Planned |
| Unreleased | local 1.35 | local 1.35 / 1.36 | exact digest pending | SecretIssuer | Planned |
| Unreleased | local 1.36 | local 1.35 / 1.36 | exact digest pending | SecretIssuer | Planned |
| Unreleased | pinned local JWT issuer | real local JWT-auth API | exact digest pending | OAuthTokenExchange RFC profile | Planned; not product compatibility |
| Unreleased | operator-verified version | operator-verified version | exact digest required | approved real provider | Not enrolled; no production acceptance |

Test actual requested APIs and skew, not merely server discovery. Future provider products get
separate rows including product version/profile, issuer/JWKS policy and CA reload evidence.
Kubernetes upstream-supported minors inform maintenance but do not automatically add support.
Supported OS image architectures target linux/amd64 and linux/arm64; each needs smoke evidence.
Chart Helm versions, Prometheus Operator CRD version, Prometheus/promtool and required Go/client-go
versions are also recorded per release. Monitoring disabled/enabled both need rendering coverage.

## Machine-readable release manifest

A completed release publishes `release-manifest.json`, versioned format `1`, containing:

- controllerVersion, chartVersion, configSchemaVersion, sourceCommit, build toolchain and dependency versions.
- image reference/index digest and per-platform digest; chart reference/OCI digest/package SHA256.
- SBOM locations/hashes and signature/provenance references.
- accepted matrix rows, evidence URIs, test dates, CA image digests and reload policies.
- tested install/upgrade/downgrade source versions, migration requirements and support status.

Digests are obtained from registry/build outputs, never predicted placeholders. Unknown fields,
missing evidence or mismatched chart appVersion/image/source commit fail promotion. Synthetic
fixtures are labeled; private evidence references do not publish private cluster inventory.

## GitHub Actions pipeline

1. PR/main validation: spec/config checks, pinned Go tests/race/vet/fuzz seeds, local API integration,
   security/license scans and Helm lifecycle tests. Read-only permissions; no real cluster access.
2. Release-candidate build: approved tag/commit from protected main, version/schema consistency,
   reproducible multiarchitecture image, SBOM, scans, Helm lint/package and matrix gates.
3. GHCR publication: job-scoped GITHUB_TOKEN with packages:write; ephemeral OIDC only for signing/
   provenance where supported. No personal access token in repository or external kubeconfig.
4. Verify registry pull by digest, chart pull/install on isolated clusters, image startup and exact
   pairing. Generate checksums/release manifest and sign image/chart digests with auditable identity.
5. Upload assets to a DRAFT GitHub Release. Promote only after mandatory acceptance, review and
   approval; stable promotion requires real adoption/monitoring evidence. A tag alone is not success.

Pin third-party Actions by commit. No release jobs on pull_request_target/untrusted fork code.
Least-privilege contents:write/packages:write/id-token:write scoped only to needed jobs; ordinary
CI has contents:read. Release concurrency keyed by version; reject overwrite of existing tags/
digests. Protected tags/environments depend on account features; if unavailable, enforce approval
through reviewed workflow/manual owner action and fail closed, not through an ineffective UI gate.

Signing/provenance implementation must be usable with chosen private/public GitHub plan. Do not
assume private artifact-attestation features are available. Verify signature/provenance consumers
on a clean environment before declaring supply-chain acceptance. A scan pass is not a signature.

## Failure, retry and rollback

Image/chart publication is not atomic across registries/assets. If any stage fails, keep release
DRAFT and mark version incomplete. Retry only missing artifacts from the same source commit;
verify existing digests, never replace them. Publish a corrective version if bytes differ.
Package publication must not trigger cluster deployment. Releasing and activating are separate.

Downgrade tests prove old binary can read preserved registry/status/Secret shapes. Otherwise the
manifest declares downgrade unsupported and provides a reviewed migration. Helm must not reset
runtime status/restart intent or delete external credentials. Normal image updates use HA rolling
strategy; leadership loss drains in-flight work. Recovery preserves all worker/CP replicas.

## Dispatch and promotion

After all `go`/`spec` checks pass on the exact main commit, the repository owner dispatches
`Paired GitHub release` with an unused version. The workflow runs only on main by its owner,
creates a draft first and never overwrites existing Git/OCI tags. Build/sign jobs alone hold
packages-write and OIDC permissions; native anonymous verification jobs have no registry login.
The final job publishes only after both platforms pass image/signature and complete Helm lifecycle
checks. Failed publication remains draft; rerun failed jobs from the same run rather than rebuilding
or replacing versioned bytes. Use a corrective version when source/artifact bytes change.

A stable version requires a separate owner-approved acceptance artifact bound to the same main
commit. Dispatch `Record owner-approved production acceptance` with the sanitized report, then
pass its immutable numeric artifact ID to the release workflow. Metadata must prove the version,
exact main SHA and unexpired artifact; report contents require all A01–A24 evidence, >=48 hours,
>=2 natural rotations, actual alert delivery and the owner's identity. Evidence references point
only to sanitized records in this public repository; no private endpoints/inventory belong in the
report. The report lives outside source so its commit binding has no circular self-reference.

Only `vX.Y.Z-rc.N` can publish without stable evidence; its manifest is explicitly experimental
with no accepted matrix rows. An RC is deployable for reviewed acceptance, not a production claim.
Package visibility must allow anonymous native pull; public source visibility alone is insufficient.

## Initial repository delivery

This commit publishes M0 documents, synthetic example and spec CI only. No v0.1.0 tag, image,
chart, placeholder release workflow or production badge is created. Real publication starts at
M5 after executable implementation and checks exist; stable release requires M7 evidence.

## References

- [GitHub image publishing](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)
- [Helm OCI registries](https://helm.sh/docs/topics/registries/)
