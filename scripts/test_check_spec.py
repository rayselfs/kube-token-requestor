import copy
import importlib.util
import json
import unittest
from pathlib import Path

MODULE = importlib.util.spec_from_file_location('check_spec', Path(__file__).with_name('check-spec.py'))
check = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(check)


class PackageChecks(unittest.TestCase):
  def setUp(self):
    self.config = json.loads((check.ROOT / 'examples/registry.json').read_text())

  def test_current_example(self):
    check.check_example(self.config)

  def test_enabled_target_rejected(self):
    self.config['clusters'][0]['enabled'] = True
    with self.assertRaises(ValueError):
      check.check_example(self.config)

  def test_output_collision_rejected(self):
    self.config['clusters'][1]['consumers'][0]['secret'] = copy.deepcopy(
      self.config['clusters'][0]['consumers'][0]['secret'])
    with self.assertRaises(ValueError):
      check.check_example(self.config)

  def test_invalid_timing_rejected(self):
    self.config['clusters'][0]['lifetime']['stopBeforeSeconds'] = 86400
    with self.assertRaises(ValueError):
      check.check_example(self.config)

  def test_real_endpoint_rejected(self):
    with self.assertRaises(ValueError):
      check.synthetic_endpoint('https://api.example.com')

  def test_credentials_in_url_rejected(self):
    with self.assertRaises(ValueError):
      check.synthetic_endpoint('https://user:fixture@api.example.invalid')

  def test_private_inventory_rejected(self):
    address = '.'.join(['10', '0', '0', '1'])
    with self.assertRaises(ValueError):
      check.check_text(address + '\n')

  def test_unclosed_fence_rejected(self):
    with self.assertRaises(ValueError):
      check.check_text('```\n')

  def test_inline_credential_rejected(self):
    self.config['clusters'][1]['provider']['client_secret'] = 'synthetic-canary'
    with self.assertRaises(ValueError):
      check.check_example(self.config)


if __name__ == '__main__':
  unittest.main()
