#!/usr/bin/env python3
"""Fetch a version/source-bound acceptance artifact from this repository only."""
import argparse
import io
import json
import re
import subprocess
import zipfile
from pathlib import Path

from release import gate, require


def extract(metadata, archive, version, commit):
  require(metadata.get('name') == 'production-acceptance-' + version and
      metadata.get('expired') is False and metadata.get('size_in_bytes', 1 << 30) <= 1 << 20,
      'Wrong, expired or oversized acceptance artifact')
  run = metadata.get('workflow_run', {})
  require(run.get('head_sha') == commit and run.get('head_branch') == 'main',
      'Acceptance must be produced from this exact main commit')
  with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
    require(bundle.namelist() == ['acceptance.json'], 'Acceptance archive has unexpected files')
    require(bundle.getinfo('acceptance.json').file_size <= 1 << 20, 'Acceptance report too large')
    data = bundle.read('acceptance.json')
  evidence = json.loads(data)
  gate(version, commit, evidence)
  return data


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--id', required=True)
  parser.add_argument('--repository', required=True)
  parser.add_argument('--version', required=True)
  parser.add_argument('--commit', required=True)
  parser.add_argument('--out', type=Path, required=True)
  args = parser.parse_args()
  require(re.fullmatch(r'[1-9]\d*', args.id), 'Acceptance artifact ID must be numeric')
  require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository), 'Invalid repository')
  endpoint = f'repos/{args.repository}/actions/artifacts/{args.id}'
  metadata = json.loads(subprocess.check_output(['gh', 'api', endpoint]))
  require(metadata.get('size_in_bytes', 1 << 30) <= 1 << 20, 'Acceptance archive too large')
  archive = subprocess.check_output(['gh', 'api', endpoint + '/zip'])
  args.out.write_bytes(extract(metadata, archive, args.version, args.commit))
  args.out.chmod(0o600)


if __name__ == '__main__':
  main()
