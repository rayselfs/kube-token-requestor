# kube-token-requestor

A shared Kubernetes credential controller designed to issue and distribute short-lived
ServiceAccount tokens to multiple Cluster Autoscalers across multiple workload clusters.

**Status: specification and implementation plan only.** No controller binary, Helm chart,
container image, release, or production compatibility has been published yet.

One Deployment serves all enrolled clusters and consumers. Two replicas provide leader-elected
HA. Enrollment is explicit; the service does not discover clusters or adopt admin kubeconfigs.

## Design

- [Normative specification](docs/spec.md)
- [Implementation plan and acceptance gates](docs/implementation-plan.md)
- [Monitoring and operations](docs/operations.md)
- [GitHub image/chart releases and compatibility matrix](docs/releases.md)
- [Disabled, synthetic multi-cluster example](examples/registry.json)
- [Security policy](SECURITY.md)

Authentication is selected per workload cluster:

1. `SecretIssuer`: a restricted issuer token held in a pre-existing management Secret.
2. `OAuthTokenExchange`: RFC 8693 exchange of a projected management workload token for a
   short-lived bearer credential trusted by the workload API.

Both supply an issuer credential. The controller then calls Kubernetes TokenRequest and writes
CA-specific management Secrets. Supporting token exchange does not imply compatibility with
all OIDC products or support for interactive SRE login and API gateways.

## Planned distribution

- Source and releases: `https://github.com/rayselfs/kube-token-requestor`
- Controller image: `ghcr.io/rayselfs/kube-token-requestor`
- OCI Helm chart: `oci://ghcr.io/rayselfs/charts/kube-token-requestor`

These are reserved publication locations, not existing artifacts. Production activation requires
accepted matrix entries and operating alerts, not merely a successful Helm installation.

## Scope

The project is environment-neutral. No company endpoints, cluster UIDs, credentials or private
infrastructure inventory belong here. Installation-specific values and approvals live in the
operator's configuration repository. No commercial access platform is required.

This initial repository intentionally has no deployable chart or automatic release workflow.
Their behavior and implementation gates are specified before credentials are managed.

## Check the specification package

```sh
python3 scripts/check-spec.py
python3 -m unittest discover -s scripts -p 'test_*.py'
```

The checks validate documentation links and the synthetic example, not runtime security.
