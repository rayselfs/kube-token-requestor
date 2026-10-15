# Security

This repository currently contains specifications, not a production controller. Do not entrust
real credentials to unimplemented or unaccepted designs.

Use GitHub private vulnerability reporting when available; otherwise contact the repository owner
privately before sharing sensitive details. Do not post tokens, keys, kubeconfigs, Secret payloads,
request bodies or private endpoints in public issues.

The eventual shared controller holds the union of enrolled issuer and output permissions.
A process compromise can affect all enrolled consumers. Namespaced Roles restrict unrelated
resources; they do not create process-level isolation between enrolled clusters. Separate
administrative trust domains require separate installations, not silent enrollment into one.

SecretIssuer authentication policy is explicit. The renewable short-lived profile grants named
issuer self-mint and PATCH on exactly its pinned management source Secret. A stolen renewable
issuer can continue minting until its authority is revoked: short token TTL is not automatic
compromise containment. Revoke the named issuer grant (and address existing tokens), or use the
reviewed identity-replacement procedure; replacing only the source bytes does not revoke stolen
predecessors. No automatic RBAC grants, admin fallback or legacy-token fallback are implemented.
Legacy long-lived sources still require independent operator rotation/revocation. See
[issuer renewal](docs/issuer-renewal.md) for trust, outage and recovery boundaries.

Only implemented, supported release/matrix entries will receive a runtime security-support claim.
Currently there are no supported runtime releases. Repository licensing is to be selected by the
owner before a public source release; no third-party source is copied into this spec package.
