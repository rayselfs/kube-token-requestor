# Stable acceptance record

Stable publication consumes an immutable GitHub Actions artifact, not a mutable file on main.
This avoids asking an evidence document to contain the Git SHA of its own commit. The owner runs
`Record owner-approved production acceptance` on the exact main commit after actual acceptance.
It validates the sanitized JSON and produces `production-acceptance-vX.Y.Z`; pass the resulting
artifact ID to `Paired GitHub release` without changing main. Artifacts expire after 30 days;
repeat owner review if evidence or source changes.

The report has exactly these fields:

| Field | Required meaning |
| --- | --- |
| version | Exact stable controller version, including `v` |
| sourceCommit | Full 40-character SHA matching the Actions run and release source |
| observationHours | Measured uninterrupted natural-lifetime observation, at least 48 |
| naturalRotations | Actual natural rotations observed, at least two |
| ownerApproval | GitHub login equal to the dispatching repository owner |
| alertDeliveryAccepted | `true` only after real failure/recovery notifications reach the receiver |
| acceptedMatrix | Nonempty list of tested, generic compatibility rows |
| scenarios | Exactly A01–A24, each with `status: passed` and sanitized evidenceURI |

Each matrix row has `managementKubernetes`, `childKubernetes`, `clusterAutoscaler`, `caImageDigest`,
`provider`, `reloadPolicy`, `architectures`, `evidenceURI` and `testedAt`. Providers/reload profiles
must be implemented selections; CA digest is actual/nonzero; both released linux architectures
must be accepted. Version strings and dates are measured facts, never planned support targets.
All evidenceURI values reference sanitized records under this public repository without query
strings. Logical names/results are enough: omit endpoints, cluster UUIDs, corporate references,
credentials and private deployment inventory.

Owner recording is an explicit review declaration. It does not run tests or turn an untested
scenario into evidence. The release job verifies source/version/schema binding and reported gates;
reviewers still assess the linked actual evidence. No current record meets these stable gates.
