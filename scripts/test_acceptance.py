import io
import json
import unittest
import zipfile
import acceptance


class AcceptanceArchive(unittest.TestCase):
  def archive(self, name='acceptance.json', content=b'{}'):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as bundle:
      bundle.writestr(name, content)
    return out.getvalue()

  def metadata(self):
    return {'name': 'production-acceptance-v0.1.0', 'expired': False, 'size_in_bytes': 100,
        'workflow_run': {'head_sha': 'a'*40, 'head_branch': 'main'}}

  def test_wrong_source_expired_or_path_traversal_rejected(self):
    for change in [{'expired': True}, {'size_in_bytes': 1 << 21},
             {'workflow_run': {'head_sha': 'b'*40, 'head_branch': 'main'}}]:
      metadata = self.metadata()
      metadata.update(change)
      with self.assertRaises(ValueError):
        acceptance.extract(metadata, self.archive(), 'v0.1.0', 'a'*40)
    with self.assertRaises(ValueError):
      acceptance.extract(self.metadata(), self.archive('../acceptance.json'), 'v0.1.0', 'a'*40)

  def test_archive_cannot_bypass_stable_gate(self):
    with self.assertRaises(ValueError):
      acceptance.extract(self.metadata(), self.archive(content=json.dumps({'sourceCommit': 'a'*40}).encode()),
                 'v0.1.0', 'a'*40)
