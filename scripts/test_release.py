import unittest
import release


class ReleaseGates(unittest.TestCase):
  def test_prerelease_does_not_claim_acceptance(self):
    self.assertEqual(release.gate('v0.1.0-rc.1', 'a'*40), 'experimental')

  def test_stable_rejects_absent_or_incomplete_acceptance(self):
    for evidence in [None, {}, {'sourceCommit': 'a'*40, 'version': 'v0.1.0',
                   'observationHours': 48, 'naturalRotations': 2}]:
      with self.assertRaises(ValueError):
        release.gate('v0.1.0', 'a'*40, evidence)

  def test_untrusted_version_or_commit(self):
    for version in ['latest', 'v0.1.0-rc.0', 'v0.1.0;echo', 'v01.1.0', 'v0.1.0\n']:
      with self.assertRaises(ValueError):
        release.gate(version, 'a'*40)
    with self.assertRaises(ValueError):
      release.gate('v0.1.0-rc.1', 'main')

  def test_evidence_is_bound_to_exact_release(self):
    evidence = {'sourceCommit': 'a'*40, 'version': 'v0.1.0', 'observationHours': 48,
          'naturalRotations': 2, 'ownerApproval': 'synthetic-test-approval',
          'alertDeliveryAccepted': True, 'acceptedMatrix': [{'managementKubernetes': '1.35.8', 'childKubernetes': '1.35.8',
          'clusterAutoscaler': '1.35.2', 'caImageDigest': 'sha256:'+'1'*64,
          'provider': 'SecretIssuer', 'reloadPolicy': 'TokenFile',
          'architectures': ['linux/amd64', 'linux/arm64'],
          'evidenceURI': 'https://github.com/example/controller/issues/1', 'testedAt': '2026-10-09'}],
          'scenarios': {f'A{i:02d}': {'status': 'passed', 'evidenceURI':
                        'https://github.com/example/controller/issues/1'} for i in range(1, 25)}}
    self.assertEqual(release.gate('v0.1.0', 'a'*40, evidence), 'accepted')
    evidence['sourceCommit'] = 'b'*40
    with self.assertRaises(ValueError):
      release.gate('v0.1.0', 'a'*40, evidence)


if __name__ == '__main__':
  unittest.main()

class ManifestChecks(unittest.TestCase):
  def assets(self, root):
    for name in ['image-linux-amd64.spdx.json', 'image-linux-arm64.spdx.json',
           'image.sigstore.json', 'chart.sigstore.json',
           'kube-token-requestor-0.1.0-rc.1.tgz', 'licenses.csv']:
      (root / name).write_bytes(b'synthetic test artifact')

  def test_platform_pair_and_asset_hashes(self):
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
      root = Path(tmp)
      self.assets(root)
      index = {'manifests': [{'platform': {'os': 'linux', 'architecture': arch},
                   'digest': 'sha256:' + str(n)*64} for n, arch in
                  enumerate(['amd64', 'arm64'], 1)]}
      args = ['v0.1.0-rc.1', 'a'*40, 'ghcr.io/example/controller',
          'ghcr.io/example/charts/controller', 'sha256:'+'a'*64, 'sha256:'+'b'*64]
      result = release.manifest(*args, index, root)
      self.assertEqual(result['supportStatus'], 'experimental')
      self.assertEqual(set(result['image']['platformDigests']), {'linux/amd64', 'linux/arm64'})
      self.assertEqual(result['acceptedMatrix'], [])
      self.assertEqual(result['assets']['licenses.csv']['sha256'], release.sha(root/'licenses.csv'))
      index['manifests'].pop()
      with self.assertRaises(ValueError):
        release.manifest(*args, index, root)

  def test_missing_or_placeholder_artifacts_are_rejected(self):
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
      with self.assertRaises(ValueError):
        release.manifest('v0.1.0-rc.1', 'a'*40, 'image', 'chart', 'sha256:'+'0'*64,
                 'sha256:'+'1'*64, {}, Path(tmp))
