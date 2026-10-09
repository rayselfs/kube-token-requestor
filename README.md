# kube-token-requestor

A shared Kubernetes credential controller designed to issue and distribute short-lived
ServiceAccount tokens to multiple Cluster Autoscalers across multiple workload clusters.

**Status: experimental paired release available; production acceptance pending.**
[v0.1.0-rc.6](https://github.com/rayselfs/kube-token-requestor/releases/tag/v0.1.0-rc.6) includes
public multiarchitecture image/OCI chart, signatures, SBOMs, full license texts and native Helm lifecycle evidence.
It is available for reviewed acceptance testing; no stable production matrix is accepted yet.

One Deployment serves all enrolled clusters and consumers. Two replicas provide leader-elected
HA. Enrollment is explicit; the service does not discover clusters or adopt admin kubeconfigs.

## Design

- [Normative specification](docs/spec.md)
- [Implementation plan and acceptance gates](docs/implementation-plan.md)
- [Acceptance evidence and remaining gaps](docs/acceptance-status.md)
- [Monitoring and operations](docs/operations.md)
- [GitHub image/chart releases and compatibility matrix](docs/releases.md)
- [Disabled, synthetic multi-cluster example](examples/registry.json)
- [Installation and upgrade](docs/installation.md)
- [Security policy](SECURITY.md)

Authentication is selected per workload cluster:

1. `SecretIssuer`: a restricted issuer token held in a pre-existing management Secret.
2. `OAuthTokenExchange`: RFC 8693 exchange of a projected management workload token for a
   short-lived bearer credential trusted by the workload API.

Both supply an issuer credential. The controller then calls Kubernetes TokenRequest and writes
CA-specific management Secrets. Supporting token exchange does not imply compatibility with
all OIDC products or support for interactive SRE login and API gateways.

## Distribution

- Source and releases: `https://github.com/rayselfs/kube-token-requestor`
- Controller image: `ghcr.io/rayselfs/kube-token-requestor`
- OCI Helm chart: `oci://ghcr.io/rayselfs/charts/kube-token-requestor`

Image and chart packages are public and tested with anonymous pulls on linux/amd64 and linux/arm64.
Use the release manifest's exact digests and verify signatures before installation.
Production activation requires
accepted matrix entries and operating alerts, not merely a successful Helm installation.

## Scope

The project is environment-neutral. No company endpoints, cluster UIDs, credentials or private
infrastructure inventory belong here. Installation-specific values and approvals live in the
operator's configuration repository. No commercial access platform is required.

The chart defaults to zero controller replicas and an empty registry. Published packages contain
the paired image digest; source values intentionally have none. Activation requires explicit
identity pins and credentials prepared through an approved channel. Runtime tests do not authorize
adoption into an external cluster.

## Check the specification package

```sh
go run ./cmd/kube-token-requestor validate-config < examples/registry.json
go test -race ./...
go vet ./...
python3 scripts/check-spec.py
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Specification checks validate documentation links and the synthetic example. Unit/race checks
cover implementation behavior; these commands alone do not establish production acceptance.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
