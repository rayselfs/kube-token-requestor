# Project instructions

- Keep source, configuration, documentation and comments in English.
- This is a generic project: never hard-code a company's topology, endpoints, identities,
  credentials, ticket identifiers or environment-specific policy.
- Follow docs/spec.md and preserve the separation between issuer acquisition and TokenRequest.
- Do not claim production acceptance without the evidence required in docs/implementation-plan.md.
- Use isolated worktrees from current origin/main for implementation; preserve other worktrees.
  Documentation-only work may use the current checkout. Initial repository bootstrapping is the
  only case without an existing remote main baseline.
- Set repository-local Git author/committer identity before committing.
- Never log/store credentials in source, fixtures, status, metrics, exceptions or command arguments.
- Tests must use synthetic credentials and local clusters. External Kubernetes/cloud systems are
  read-only until the owner approves an exact mutation scope.
- Do not implement fallback authentication, admin kubeconfig adoption, automatic RBAC grants,
  or workload replica changes outside the explicitly guarded CA lifecycle.
- Keep the Go design small: typed clients, client-go workqueue/leader election, explicit errors.
- Before a push, run the specification checks. Implementation adds race/unit/integration, Helm,
  security and release verification appropriate to the change.
