"""Offline maintenance guards; no cluster, certificates or credentials created."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('renew', Path(__file__).with_name('renew-p2-redis-tls.py'))
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class RenewalGuards(unittest.TestCase):
    def run_case(self, change=None, sent=False):
        with tempfile.TemporaryDirectory(prefix='redis-renew-guard-') as directory:
            root = Path(directory)
            records = root/'redis-tls-renew7d'
            records.mkdir()
            if sent:
                (records/'mutation.sent.json').write_text('{}')
            calls = []
            def command(argv, **kwargs):
                calls.append(argv)
                self.assertEqual(argv[0], 'kubectl')
                args = argv[argv.index('-n')+2:]
                if args[:2] == ['get', 'pod']:
                    value = {'metadata': {'uid': M.POD_UID, 'ownerReferences': [
                        {'controller': True, 'kind': 'ReplicaSet', 'name': 'rs', 'uid': 'rs-uid'}]},
                        'status': {'containerStatuses': [{'ready': True}]},
                        'spec': {'containers': [{'args': [item for key, name in
                            [('tls-cert-file', 'server.pem'), ('tls-key-file', 'server-key.pem'), ('tls-ca-cert-file', 'ca.pem')]
                            for item in ['--'+key, M.REMOTE+'/'+name]]}]}}
                    if change == 'pod': value['metadata']['uid'] = 'replacement'
                elif args[:2] == ['get', 'replicaset']:
                    value = {'metadata': {'uid': 'rs-uid', 'ownerReferences': [
                        {'controller': True, 'uid': 'dd724dc4-ad59-4a78-b5bb-50aba907e036'}]}}
                elif args[:2] == ['get', 'deployment']:
                    value = {'metadata': {'uid': 'dd724dc4-ad59-4a78-b5bb-50aba907e036'}}
                else:
                    self.assertEqual(args[0], 'exec')
                    r = args[args.index('--raw')+1:]
                    if r == ['INFO', 'server']:
                        text = 'run_id:'+('replacement' if change == 'run' else M.RUN)+'\r\nredis_version:7.4.11\r\nprocess_id:1\r\n'
                    elif r == ['ACL', 'LIST']:
                        text = 'changed ACL'
                    else:
                        self.fail('unexpected mutation or unsupported command')
                    return subprocess.CompletedProcess(argv, 0, text.encode(), b'')
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b'')

            class Assembly:
                KNOWN = {'Redis': {'File': 'old', 'SHA256': 'old'}}
                @staticmethod
                def obj(pin):
                    if pin.get('File') == 'old': return {'KeeperSelection': {}}
                    return {'ServerName': M.SERVER, 'Port': 6380, 'Native': {'PodUID': M.POD_UID},
                            'CA': {}, 'KeeperCredential': {}, 'ReaderCredential': {}, 'CustodyKey': {}}
                @staticmethod
                def read(pin): return b'private'

            class FakeStat:
                st_mode = 0o40700
            # Windows does not represent POSIX permissions; permission logic is
            # isolated here, while journal existence and cleanup use real files.
            original_stat = Path.stat
            def stat(path, *args, **kwargs):
                if path == records: return FakeStat()
                return original_stat(path, *args, **kwargs)
            with patch.object(M, 'ROOT', root), patch.object(M, 'os', SimpleNamespace(name='posix', umask=lambda _: None)), \
                 patch.object(M.importlib.util, 'module_from_spec', return_value=Assembly), \
                 patch('importlib.machinery.SourceFileLoader.exec_module'), \
                 patch.object(M.subprocess, 'run', side_effect=command), patch.object(Path, 'stat', stat):
                with self.assertRaises(ValueError) as error:
                    M.main()
            self.assertFalse(any('SET' in call for call in calls))
            return str(error.exception), calls

    def test_unknown_mutation_not_replayed(self):
        message, calls = self.run_case(sent=True)
        self.assertIn('already sent', message)
        self.assertEqual(calls, [])

    def test_replacement_pod_refused(self):
        self.assertIn('Pod changed', self.run_case('pod')[0])

    def test_restarted_process_refused(self):
        self.assertIn('process changed', self.run_case('run')[0])

    def test_acl_change_refused(self):
        self.assertIn('ACL changed', self.run_case('acl')[0])


if __name__ == '__main__':
    unittest.main()
