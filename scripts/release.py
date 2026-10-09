#!/usr/bin/env python3
"""Validate release gates and generate a paired, digest-derived artifact manifest."""
import argparse
import hashlib
import json
import re
import math
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

VERSION = re.compile(r'^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-rc\.([1-9]\d*))?$')
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')


def require(value, message):
  if not value:
    raise ValueError(message)


def gate(version, commit, evidence=None):
  require(VERSION.fullmatch(version), 'Version must be stable SemVer or an explicit rc prerelease')
  require(COMMIT.fullmatch(commit), 'Source commit must be a full Git commit')
  if '-rc.' in version:
    return 'experimental'
  require(evidence is not None, 'Stable publication requires accepted production evidence')
  require(set(evidence) == {'sourceCommit', 'version', 'observationHours', 'naturalRotations',
                'ownerApproval', 'alertDeliveryAccepted', 'acceptedMatrix', 'scenarios'},
      'Acceptance report has unknown or missing fields')
  require(evidence.get('sourceCommit') == commit and evidence.get('version') == version,
      'Acceptance must bind this exact source and version')
  require(type(evidence.get('observationHours')) in (int, float) and
      math.isfinite(evidence['observationHours']) and evidence['observationHours'] >= 48 and
      type(evidence.get('naturalRotations')) is int and evidence['naturalRotations'] >= 2,
      'Stable publication requires natural-lifetime observation')
  require(isinstance(evidence.get('ownerApproval'), str) and
      re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}', evidence['ownerApproval']) and
      evidence.get('alertDeliveryAccepted') is True,
      'Stable publication requires owner approval and alert delivery')
  require(evidence.get('acceptedMatrix'), 'Stable publication requires an accepted matrix')
  for row in evidence['acceptedMatrix']:
    require(isinstance(row, dict) and set(row) == {'managementKubernetes', 'childKubernetes',
        'clusterAutoscaler', 'caImageDigest', 'provider', 'reloadPolicy', 'architectures',
        'evidenceURI', 'testedAt'}, 'Invalid accepted matrix row')
    require(row['provider'] in ('SecretIssuer', 'OAuthTokenExchange') and
        row['reloadPolicy'] in ('TokenFile', 'StopStart'), 'Unknown accepted profile')
    require(DIGEST.fullmatch(row['caImageDigest']) and row['caImageDigest'] != 'sha256:' + '0'*64,
        'CA digest is required')
    require(len(row['architectures']) == 2 and
        set(row['architectures']) == {'linux/amd64', 'linux/arm64'}, 'Both architectures need acceptance')
    for field in ('managementKubernetes', 'childKubernetes', 'clusterAutoscaler'):
      require(re.fullmatch(r'1\.(34|35|36)\.(0|[1-9]\d*)', row[field]), 'Unsupported version profile')
    require(row['childKubernetes'].split('.')[1] == row['clusterAutoscaler'].split('.')[1],
        'CA/child minor mismatch requires a separate reviewed compatibility contract')
    date.fromisoformat(row['testedAt'])
    evidence_uri(row['evidenceURI'])
  rows = evidence.get('scenarios', {})
  require(set(rows) == {f'A{i:02d}' for i in range(1, 25)}, 'Acceptance scenario set is incomplete')
  for row in rows.values():
    require(isinstance(row, dict) and set(row) == {'status', 'evidenceURI'} and
        row['status'] == 'passed', 'Every production scenario requires accepted evidence')
    evidence_uri(row['evidenceURI'])
  return 'accepted'


def evidence_uri(value):
  parsed = urlsplit(value)
  require(parsed.scheme == 'https' and parsed.hostname == 'github.com' and
      parsed.username is None and not parsed.query and parsed.path.count('/') >= 3,
      'Evidence must reference sanitized GitHub records without credentials or query strings')


def sha(path):
  return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(version, commit, image, chart, image_digest, chart_digest, index, assets, evidence=None):
  support = gate(version, commit, evidence)
  for digest in [image_digest, chart_digest]:
    require(DIGEST.fullmatch(digest) and digest != 'sha256:' + '0'*64, 'Invalid artifact digest')
  platforms = {}
  for item in index.get('manifests', []):
    platform = item.get('platform', {})
    if platform.get('os') != 'linux' or platform.get('architecture') not in ('amd64', 'arm64'):
      continue
    key = 'linux/' + platform['architecture']
    require(key not in platforms and DIGEST.fullmatch(item.get('digest', '')), 'Invalid image platform')
    platforms[key] = item['digest']
  require(set(platforms) == {'linux/amd64', 'linux/arm64'}, 'Both image platforms are required')
  names = sorted(p.name for p in assets.iterdir() if p.is_file() and p.name != 'release-manifest.json')
  required = {'image-linux-amd64.spdx.json', 'image-linux-arm64.spdx.json', 'image.sigstore.json',
        'chart.sigstore.json', f'kube-token-requestor-{version[1:]}.tgz', 'licenses.csv', 'licenses.tgz'}
  require(required <= set(names), 'Missing release assets')
  return {
    'formatVersion': 1, 'controllerVersion': version, 'chartVersion': version[1:],
    'configSchemaVersion': 1, 'sourceCommit': commit, 'supportStatus': support,
    'toolchain': {'go': '1.26.9', 'clientGo': '0.35.9', 'helm': '4.1.3', 'trivy': '0.75.0',
           'cosign': '3.1.3', 'promtool': '3.15.0'},
    'image': {'reference': image, 'indexDigest': image_digest, 'platformDigests': platforms},
    'chart': {'reference': chart, 'ociDigest': chart_digest,
          'packageSHA256': sha(assets / f'kube-token-requestor-{version[1:]}.tgz')},
    'assets': {name: {'sha256': sha(assets / name)} for name in names},
    'acceptedMatrix': evidence.get('acceptedMatrix', []) if evidence else [],
    'provenance': {'type': 'BuildKit', 'reference': image + '@' + image_digest,
            'signingIssuer': 'https://token.actions.githubusercontent.com'},
    'upgrade': {'testedFrom': [], 'downgradeSupported': False,
          'requirement': 'Review preserved registry/status/credential schemas before changing versions'},
  }


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('action', choices=['gate', 'manifest'])
  parser.add_argument('--version', required=True)
  parser.add_argument('--commit', required=True)
  parser.add_argument('--evidence', type=Path)
  parser.add_argument('--assets', type=Path)
  parser.add_argument('--index', type=Path)
  parser.add_argument('--image')
  parser.add_argument('--chart')
  parser.add_argument('--image-digest')
  parser.add_argument('--chart-digest')
  args = parser.parse_args()
  require(VERSION.fullmatch(args.version), "Invalid version")
  evidence = json.loads(args.evidence.read_text()) if args.evidence else None
  if args.action == 'gate':
    print(gate(args.version, args.commit, evidence))
    return
  result = manifest(args.version, args.commit, args.image, args.chart, args.image_digest,
           args.chart_digest, json.loads(args.index.read_text()), args.assets, evidence)
  (args.assets / 'release-manifest.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
  main()
