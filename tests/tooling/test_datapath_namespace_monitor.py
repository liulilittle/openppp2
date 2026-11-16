"""Teardown must be auditable without weakening the live-process stop."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from datapath_namespace_monitor import verify_child


class NamespaceMonitorTest(unittest.TestCase):
    before = dict(start='123', net='net:[456]', exe='/task/ppp')

    def verify(self, after, mounts, known=None, output=''):
        return verify_child('42', self.before, '/task/ppp', ('net:[1]',),
                            set() if known is None else known,
                            snapshot=lambda pid: after, names=lambda: mounts,
                            query=lambda pid: dict(stdout=output, stderr='', returncode=0))

    def test_exited_during_identify(self):
        result = self.verify(None, {})
        self.assertEqual(result['decision'], 'process-exited')
        self.assertEqual(result['pid'], 42)
        self.assertEqual(result['before']['net'], 'net:[456]')
        self.assertEqual(result['identify']['stdout'], '')

    def test_exited_before_namespace_read(self):
        result = verify_child('42', None, '/task/ppp', ('net:[1]',), set(),
                              snapshot=lambda pid: None, names=lambda: {},
                              query=lambda pid: dict(stdout='', stderr='gone', returncode=1))
        self.assertEqual(result['decision'], 'process-exited')
        self.assertEqual(result['identify']['stderr'], 'gone')

    def test_previously_verified_namespace_unmounted(self):
        known = {('42', '123', 'net:[456]')}
        self.assertEqual(self.verify(self.before, {}, known)['decision'], 'namespace-gone')

    def test_alive_unknown_namespace_stops(self):
        self.assertEqual(self.verify(self.before, {})['decision'], 'STOP-unexpected-namespace')
        moved = dict(self.before, net='net:[1]')
        known = {('42', '123', 'net:[456]')}
        self.assertEqual(self.verify(moved, {}, known)['decision'], 'STOP-unexpected-namespace')

    def test_named_child_verified_and_pid_reuse_rejected(self):
        known = set()
        result = self.verify(self.before, {'pppmat-c-1': 'net:[456]'}, known, 'pppmat-c-1')
        self.assertEqual(result['decision'], 'verified')
        self.assertIn(('42', '123', 'net:[456]'), known)
        reused = dict(self.before, start='124')
        self.assertEqual(self.verify(reused, {}, known)['decision'], 'process-exited')
        self.assertEqual(self.verify(self.before, {'other': 'net:[456]'}, known)['decision'],
                         'STOP-unexpected-namespace')


if __name__ == '__main__':
    unittest.main()
