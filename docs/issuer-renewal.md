# Automatic short-lived issuer renewal

Status: implementation under review, not a released/accepted runtime profile. Existing released
profiles do not gain permissions or change behavior on upgrade without explicit enrollment.
The goal is one secure bootstrap followed by unattended source AND consumer renewal, across
normal restarts and HA leader changes. A periodic manual source rotation is not this profile.

## Enrollment and least privilege

Start from [the disabled synthetic example](../examples/renewable-registry.json).
`provider.type=SecretIssuer`, `longLived=false`, and a complete `provider.renewal` object are
required. Renewal uses the same Lifetime field names as consumer policy, with independent
validation. A typical policy requests86400s, accepts79200..90000s, renews with43200s remaining,
and stops acquisition inside1800s+60s skew. No magic TTL/audience or fallback identity is used.
The child API must accept the requested lifetime; shortened/excessive responses fail closed.

The optional [child Role/Binding](../bootstrap/renewable-issuer-role.yaml) adds only
`create serviceaccounts/token` for the exact issuer SA in its identity namespace. Consumer
mint grants remain individually named. All legacy/OAuth issuer permission reviews still reject
unregistered self-mint, foreign SA names, wildcards, Secret access and RBAC/Node/CAPI writes.
The controller never provisions these grants. The chart adds only GET/PATCH for the exact source
Secret; no CREATE/DELETE/LIST/WATCH or source namespace-wide write permission is added.
No long-lived ServiceAccount-token Secret, new CronJob, component or dependency is required.

The source remains an existing mutable Opaque Secret, exactly ca.crt/token, pinned namespace,
name, UID and public CA hash. Bootstrap must supply a valid short-lived token for the pinned
issuer SA. Credentials stay in memory/API storage and never appear in values, errors, metrics,
status or event bodies. Kubernetes Secret encryption/access policies remain prerequisites.

## Renewal transaction

1. On the elected per-cluster queue, acquire and authenticate current source against the pinned
   child API. Verify kube-system/issuer SA UIDs, principal/groups and effective named permissions.
   The enabled cluster drives renewal independently of consumer expiry or enabled flags.
   Disabled clusters, invalid configuration and standby replicas cannot renew.
2. If the issuer is not yet due, use the existing token. When due, read exact source metadata/data;
   require it matches the authenticated predecessor. Recheck live leader, registry UID/generation
   and accepted status generation before issuing. Request only the pinned issuer SA, exact
   enrolled audiences and configured bounded TTL. No consumer replica change is needed.
3. Validate successor claims: SA subject/name/namespace/UID, audiences, issued/not-before/expiry,
   TTL bounds and TokenRequest expiration timestamp. Then use the successor over validated TLS
   for actual issuer identity, pinned SA, self-mint and full effective grant review. Positive
   consumer SA/permission checks happen only before that consumer is issued a token;
   successor validation does not scan100 accounts per source renewal. A missing consumer account/grant cannot block source renewal or healthy siblings. Foreign
   grants remain rejected even outside the current slice. Decoding a JWT alone is insufficient.
4. Recheck leadership/configuration. UID/resourceVersion JSON Patch tests bind a replacement of
   only `/data/token`; reject non-increasing expiry. Keep source UID, CA, keys, annotations and
   other metadata. Read back the exact successor. Consumers use the authenticated new issuer.

Token minting does not revoke the predecessor. A crash before CAS leaves a usable predecessor;
a crash/lost response after CAS lets the next reconciliation/leader read the persisted successor.
Concurrent operator updates, replacement Secrets, or stale leaders fail CAS rather than overwrite
newer material. A token minted but not published can expire unused; retries never roll source back.
Cross-object Lease/config checks and Secret CAS are separate API transactions, not atomic fencing.
Renewal follows the existing bounded retry queue and honors API Retry-After; trust/authentication
failures require reviewed input repair. One cluster failure does not enroll another identity.

## HA, recovery and revocation

Two controller replicas elect one leader. Both rely on the durable source, not process memory.
Early renewal leaves an outage budget; it does not guarantee recovery after all valid source
credentials have expired. Prolonged outage, issuer revocation, lost source or changed SA UID
requires secure rebootstrap of only that enrollment. Keep workers, templates and node pools;
existing consumer-token safety-stop/recovery policies continue to apply. Never silently acquire
admin credentials, switch to a legacy long-lived token, restore stale source bytes or clear latches.

A stolen issuer can mint successors indefinitely while named self-mint authority remains.
Short JWT TTL does not revoke that capability. Incident response must revoke the issuer authority
and account for already issued tokens, or replace the dedicated identity under reviewed UID/RBAC
changes. Updating source bytes alone does not revoke an attacker-held predecessor. Routine
source renewal and emergency revocation are different operations.

## Monitoring and acceptance

The leader exports issuer expiry, automatic renewal due timestamp and `kube_token_requestor_issuer_renewal_total{cluster,result}`.
The counter covers the whole due renewal, including validation/CAS/readback failures; no bearer,
Secret version or token-derived labels. Standbys do not export target series. Existing consumer
expiry/bootstrap alerts remain; the chart also alerts after automatic source renewal is overdue for2m. The due metric is emitted
only for this profile, so healthy short-lived OAuth credentials do not trigger source-renewal alerts.
Rendering rules is not proof of a working monitoring backend or delivered notification.

Required synthetic TLS/fake-client tests cover actual successor authentication, wrong
SA/UID/audience/TTL/expiry/principal/permissions, lost leadership before mint/publication,
source drift/CAS conflict, post-CAS response loss, persisted successor after leader restart,
independent consumer scheduling, Retry-After, expired-source rejection, opt-in-only RBAC/schema
and no CA/source-trust/metadata changes. Race/unit, Helm, security and existing profile checks
must pass before release. No local Kubernetes cluster is required by these new tests.

Before live adoption, pin a paired release image/chart, review exact source/child RBAC diff,
stop requestor and drain affected CA for provider policy change, stage disabled old/new targets,
validate source and new policy, then activate under separate approval. Accept a real source
renewal and consumer reload plus leader recovery on the intended service. Existing consumer
reload evidence does not prove this new source profile. Do not publish a production-accepted
matrix row until actual profile evidence exists; avoid a fixed24h wait when bounded policy
and attended runtime evidence can exercise the required sequence safely.
