import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock
import subprocess

spec = importlib.util.spec_from_file_location('forward', Path(__file__).with_name('p2-vault-local-forward.py'))
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)

class ProviderSelectionTests(unittest.TestCase):
    def fixture(self):
        uid = 'ef729a97-9c4d-4276-a6d5-68350ef46607'
        service = {'metadata':{'namespace':F.NS,'name':'vault','uid':uid},
                   'spec':{'type':'ClusterIP','selector':{'app':'vault'}}}
        pod = {'metadata':{'namespace':F.NS,'name':'vault-pod','uid':'pod-uid','labels':{'app':'vault'}},
               'status':{'phase':'Running','containerStatuses':[{'ready':True}]}}
        slices = {'items':[{'metadata':{'namespace':F.NS,'ownerReferences':[
            {'controller':True,'kind':'Service','uid':uid}]},
            'ports':[{'port':8200,'protocol':'TCP'}],
            'endpoints':[{'conditions':{'ready':True},'targetRef':{
                'namespace':F.NS,'kind':'Pod','name':'vault-pod','uid':'pod-uid'}}]}]}
        flags = {'--provider-service':'vault','--provider-endpoint':'https://vault.'+F.NS+'.svc:8200'}
        return service,slices,pod,flags

    def test_current_owned_endpoint(self):
        args = self.fixture()
        before = copy.deepcopy(args)
        self.assertEqual(F.select_provider(*args),('vault-pod','pod-uid'))
        self.assertEqual(args,before)

    def test_replacement_unready_foreign_and_ambiguous_endpoints_refuse(self):
        for case in range(7):
            s,e,p,f = self.fixture()
            if case == 0: p['metadata']['uid'] = 'replaced'
            if case == 1: p['status']['containerStatuses'][0]['ready'] = False
            if case == 2: e['items'][0]['metadata']['ownerReferences'][0]['uid'] = 'foreign'
            if case == 3: e['items'][0]['endpoints'] *= 2
            if case == 4: f['--provider-endpoint'] = 'https://127.0.0.1:8200'
            if case == 5: s['metadata']['uid'] = 'replaced'
            if case == 6: p['metadata']['labels']['app'] = 'other'
            with self.subTest(case=case), self.assertRaises(ValueError):
                F.select_provider(s,e,p,f)

class ForwardCleanupTests(unittest.TestCase):
    def test_terminates_only_its_process(self):
        forward = F.LocalForward(None,None,None,None)
        forward.process = Mock()
        forward.process.poll.return_value = None
        forward.log = Mock()
        forward.__exit__(None,None,None)
        forward.process.terminate.assert_called_once()
        forward.process.wait.assert_called_once_with(timeout=5)
        forward.process.kill.assert_not_called()
        forward.log.close.assert_called_once()

    def test_kills_its_process_when_graceful_shutdown_times_out(self):
        forward = F.LocalForward(None,None,None,None)
        forward.process = Mock()
        forward.process.poll.return_value = None
        forward.process.wait.side_effect = [subprocess.TimeoutExpired('kubectl',5),0]
        forward.log = Mock()
        forward.__exit__(None,None,None)
        forward.process.kill.assert_called_once()
        self.assertEqual(forward.process.wait.call_count,2)
        forward.log.close.assert_called_once()

if __name__ == '__main__':
    unittest.main()
