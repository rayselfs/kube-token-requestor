#!/usr/bin/env python3
"""Check the specification package, not runtime enrollment or security acceptance."""
import ipaddress
import json
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
  if not condition:
    raise ValueError(message)


def synthetic_endpoint(value):
  parsed = urlsplit(value)
  require(parsed.scheme == 'https' and parsed.hostname and
      parsed.hostname.endswith('.example.invalid') and not parsed.username and
      not parsed.password and not parsed.query and not parsed.fragment,
      'Example endpoints must be credential-free synthetic HTTPS URLs')


def check_text(text):
  require(text.endswith('\n') and '\r' not in text, 'Text must use LF and a final newline')
  require(not any(line.endswith((' ', '\t')) for line in text.splitlines()),
      'Trailing whitespace is forbidden')
  require(text.count('```') % 2 == 0, 'Unclosed fenced code block')
  for address in re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', text):
    parsed = ipaddress.ip_address(address)
    require(parsed.is_global, 'Private network inventory must not be published')
  require(not re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', text),
      'Private key material is forbidden')
  require(not re.search(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', text),
      'JWT material is forbidden')


def check_example(config):
  require(config['schemaVersion'] == 1, 'Unsupported example schema')
  uuid.UUID(config['managementUID'])
  clusters = config['clusters']
  require(len(clusters) == 2, 'Example must show two workload clusters')
  require(sum(len(c['consumers']) for c in clusters) == 3, 'Example must show three CAs')
  require({c['provider']['type'] for c in clusters} == {'SecretIssuer', 'OAuthTokenExchange'},
      'Both provider examples are required')
  ids, refs = set(), set()
  for cluster in clusters:
    require(cluster['enabled'] is False, 'Example targets must be disabled')
    require(cluster['id'] not in ids, 'Duplicate cluster ID')
    ids.add(cluster['id'])
    synthetic_endpoint(cluster['endpoint'])
    uuid.UUID(cluster['kubeSystemUID'])
    require(re.fullmatch('[0-9a-f]{64}', cluster['caSHA256']), 'Invalid CA hash')
    life = cluster['lifetime']
    require(life['acceptedMaxSeconds'] >= life['requestedSeconds'] >= life['acceptedMinSeconds'] >
        life['renewBeforeSeconds'] > life['stopBeforeSeconds'] > life['clockSkewSeconds'] > 0,
        'Invalid example timing budget')
    provider = cluster['provider']
    if provider['type'] == 'SecretIssuer':
      require(provider['longLived'] is True, 'Example issuer policy must be explicit')
      require(provider['rotationPeriodSeconds'] > 0, 'Rotation policy required')
      uuid.UUID(provider['serviceAccount']['uid'])
      source = provider['secret']
      uuid.UUID(source['uid'])
      refs.add((source['namespace'], source['name']))
    else:
      synthetic_endpoint(provider['tokenEndpoint'])
      synthetic_endpoint(provider['subjectTokenAudience'])
      synthetic_endpoint(provider['audience'])
      require(0 < provider['acceptedMinSeconds'] < provider['acceptedMaxSeconds'],
          'Invalid exchange TTL')
      for ref in [provider['trustSecret'], provider['clientSecret']]:
        uuid.UUID(ref['uid'])
        key = (ref['namespace'], ref['name'])
        require(key not in refs, 'Duplicate credential reference')
        refs.add(key)
    for consumer in cluster['consumers']:
      require(consumer['enabled'] is False, 'Example consumers must be disabled')
      require(consumer['id'] not in ids, 'Duplicate consumer ID')
      ids.add(consumer['id'])
      require(consumer['reloadPolicy'] in ['StopStart', 'TokenFile'], 'Invalid reload policy')
      uuid.UUID(consumer['serviceAccount']['uid'])
      uuid.UUID(consumer['caDeployment']['uid'])
      require(re.fullmatch('sha256:[0-9a-f]{64}', consumer['caDeployment']['imageDigest']),
          'Invalid image digest')
      ref = consumer['secret']
      uuid.UUID(ref['uid'])
      key = (ref['namespace'], ref['name'])
      require(key not in refs, 'Conflicting output reference')
      refs.add(key)
  require(not re.search(r'"(?:token|password|privateKey|client_secret)"\s*:', json.dumps(config)),
      'Example must contain references, not credential values')


def main():
  documents = [ROOT / 'README.md', ROOT / 'AGENTS.md', ROOT / 'SECURITY.md',
         *sorted((ROOT / 'docs').glob('*.md'))]
  for path in documents:
    text = path.read_text()
    check_text(text)
    for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)', text):
      if not target.startswith(('https://', 'http://', '#')):
        resolved = (path.parent / target.split('#')[0]).resolve()
        require(resolved.is_relative_to(ROOT) and resolved.is_file(), 'Broken local document link')
  spec = (ROOT / 'docs/spec.md').read_text()
  require(set(re.findall(r'REQ-(\d+):', spec)) == {f'{i:02}' for i in range(1, 18)},
      'Specification requirement IDs are incomplete')
  plan = (ROOT / 'docs/implementation-plan.md').read_text()
  require(set(re.findall(r'\| A(\d+) \|', plan)) == {f'{i:02}' for i in range(1, 25)},
      'Acceptance case IDs are incomplete')
  example = (ROOT / 'examples/registry.json').read_text()
  check_text(example)
  check_example(json.loads(example))
  print('Specification package passed; runtime compatibility and production readiness are unverified.')


if __name__ == '__main__':
  try:
    main()
  except (ValueError, KeyError, TypeError, OSError):
    print('Specification package validation failed; inspect documents/example locally.', file=sys.stderr)
    sys.exit(1)
