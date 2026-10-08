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

SecretIssuer uses a long-lived bearer credential by default. This is an explicit operational
tradeoff, not Kubernetes' preferred authentication approach. Its required rotation, revocation,
access-control and backup handling are defined in the specification and operations guide.

Only implemented, supported release/matrix entries will receive a runtime security-support claim.
Currently there are no supported runtime releases. Repository licensing is to be selected by the
owner before a public source release; no third-party source is copied into this spec package.
