"""Local parser/env/FD models only; no claim of native DNS/mount qualification."""
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('original_dns_bridge', Path(__file__).with_name('system-backup-c1-host-mysql-bridge.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class OriginalDNSTransportModels(unittest.TestCase):
    def resolver(self, raw, directory):
        source = Path(directory)/'actual-resolv.conf'
        source.write_bytes(raw)
        proc_path = '/proc/123/root/etc/resolv.conf'
        original_open = os.open
        fds = []
        def actual_file_open(path, flags, *args):
            self.assertEqual(path, proc_path)
            fd = original_open(source, flags, *args)
            fds.append(fd)
            return fd
        native = SimpleNamespace(NS='clawmanager-zhanghui08-system', mounts=lambda pid: [{'path': '/etc/resolv.conf', 'id': 91}], process=lambda pid: {'pid': pid}, same_process=lambda a, c: a == c)
        with patch.object(b.os, 'open', side_effect=actual_file_open):
            result = b.original_resolver({'pid': {'pid': 123}}, native)
        return result, source, fds

    def test_real_fd_bytes_preserve_original_nameserver_search_and_inode(self):
        raw = b'nameserver 10.96.0.10\nsearch clawmanager-zhanghui08-system.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n'
        with tempfile.TemporaryDirectory() as directory:
            result, source, fds = self.resolver(raw, directory)
            try:
                self.assertEqual(b.resolver_bytes(result['fd']), raw)
                self.assertEqual(result['cluster_domain'], 'cluster.local')
                self.assertEqual(result['nameservers'], ['10.96.0.10'])
                self.assertEqual(result['inode']['inode'], source.stat().st_ino)
                self.assertEqual(fds, [result['fd']])
            finally:
                os.close(result['fd'])

    def test_loopback_unknown_or_ambiguous_cluster_dns_is_refused(self):
        cases = [
            b'nameserver 127.0.0.53\nsearch clawmanager-zhanghui08-system.svc.cluster.local\n',
            b'nameserver 0.0.0.0\nsearch clawmanager-zhanghui08-system.svc.cluster.local\n',
            b'nameserver 10.96.0.10\nsearch unrelated.svc.cluster.local\n',
            b'nameserver 10.96.0.10\nsearch clawmanager-zhanghui08-system.svc.cluster.local clawmanager-zhanghui08-system.svc.other.local\n',
        ]
        with tempfile.TemporaryDirectory() as directory:
            for raw in cases:
                with self.subTest(raw=raw):
                    with self.assertRaises(b.Refused):
                        self.resolver(raw, directory)

    def test_go_dns_uses_bound_file_without_dropping_other_runtime_settings(self):
        environment = {'GODEBUG': 'x509sha1=0,netdns=cgo,tlsrsakex=0', 'LOCALDOMAIN': 'foreign.example', 'RES_OPTIONS': 'rotate', 'HOSTALIASES': '/foreign', 'KUBECONFIG': '/original/kubeconfig', 'ORIGINAL_VALUE': 'unchanged'}
        with patch.dict(os.environ, environment, clear=True):
            selected = b.caller_environment()
            self.assertEqual(selected['GODEBUG'], 'x509sha1=0,tlsrsakex=0,netdns=go')
            self.assertTrue(all(key not in selected for key in ('LOCALDOMAIN', 'RES_OPTIONS', 'HOSTALIASES')))
            self.assertEqual(selected['KUBECONFIG'], '/original/kubeconfig')
            self.assertEqual(selected['ORIGINAL_VALUE'], 'unchanged')
            self.assertEqual(dict(os.environ), environment)


if __name__ == '__main__':
    unittest.main()
