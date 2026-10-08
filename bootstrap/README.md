# Child identity bootstrap

These are reviewable examples, not chart hooks or automatic enrollment. Use a dedicated child
namespace and unique names; review existing names before creating anything. Apply only through
the operator's approved child bootstrap workflow after verifying the target API identity.
Do not run against a current context implicitly. The controller never applies these files.

`secret-issuer.yaml` creates one issuer and one independent CA identity. The issuer can create
tokens only for `ca-one`, get the named accounts, read the child identity namespace and perform
self-reviews. It cannot create its own token. The CA has read-only scheduling/discovery grants,
named identity reads and namespaced events. There are no Secret reads, RBAC writes, CAPI writes,
node writes or eviction grants. The example is for scale-up-only operation; scale-down/drain
requires a separate CA permissions and policy review. Check optional/new API requirements against
the exact accepted CA image; do not automatically broaden these grants to cure errors.

For more CAs, create separate accounts and exact TokenRequest resourceNames. Add each to the
appropriate bindings and named account reads; never reuse the issuer as a CA. CAPI discovery and
scaling rights belong to the CA's independent management identity and are outside this example.
Cluster-scoped read grants are required for child scheduling data, not management enrollment.

Bootstrap credentials through a secure operator runner directly from the child API to a
pre-existing management Opaque Secret. Do not put token payloads in Helm values, terminal output,
command arguments, local files or this repository. Record actual object UIDs and public CA hash
in the registry only after creation. Use independent human/bootstrap and controller identities.

The source issuer's lifetime is an explicit operator policy. A bounded source token needs an
independent renewal mechanism and cannot be self-renewed by this controller. A legacy dedicated
ServiceAccount-token Secret is a long-lived bootstrap credential: it requires an approved
rotation/revocation owner, encrypted storage and a pinned management Secret with `rotated-at`.
This example deliberately creates no long-lived credential. Do not use a cluster-admin kubeconfig
or a human refresh token as the source.

OAuth enrollment replaces the issuer SA subject with the exact API-authenticated username/groups.
The operator configures JWT/API trust and binds that principal to equivalent named issuer rights.
Do not add it to `system:masters`, impersonate a ServiceAccount or infer trust from discovery alone.
The RFC profile still requires its own actual authentication/rotation acceptance evidence.
