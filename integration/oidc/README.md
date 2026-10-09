# Synthetic OAuth/JWT API fixture

This is test code, not a broker product or a component shipped in the controller image.
It uses go-jose for signing, real Kubernetes TokenReview for subject verification, and
an exact subject UID/username/groups/audience. Signing/TLS keys and exchanged tokens remain
in process memory; the test exports only its public TLS certificate. Responses/errors omit
credential material. Runtime dependencies and required notices remain separate from fixtures.

Normal race tests exercise protocol rejection and signer/client/subject changes with a fake
review transport. They are not actual API acceptance.

On a Linux Docker host with pinned kind v0.33.0 available:

```sh
REQUESTOR_OIDC_API=1 go test -v -count=1 -timeout=15m ./integration/oidc -run '^TestActualKubernetes$'
```

The opt-in test creates a uniquely named `requestor-oidc-*` network and kind cluster with
Kubernetes 1.35.8, then removes only those generated resources. Bootstrap uses that freshly
created API's protected temporary kubeconfig after checking loopback addressing and exact
node ownership. Broker TokenReview and provider Secret reads use independent restricted
ServiceAccount clients. The exchanged JWT is authenticated by the real API's OIDC verifier,
with a prefixed identity bound only to the named CA TokenRequest and identity reads/reviews.

The test checks actual issuer/consumer effective permissions, wrong API UID/CA rejection,
named TokenRequest, JWKS predecessor rejection after refresh, client Secret CAS rotation,
actual subject-account UID revocation and independence of the already-issued CA credential.
The fake reviewer used during discovery bootstrap cannot authenticate any subject and is
replaced with the real restricted reviewer before exchanges begin.

The native amd64/arm64 workflow uses fresh runners and no external kubeconfigs or cloud
credentials. This single-API fixture does not prove deployed-controller projected-volume
rotation, a selected vendor's exchange product, actual CA reload, capacity or long-run
acceptance. Those require separate measured evidence; do not turn a passing fixture into
an arbitrary OIDC compatibility claim.
