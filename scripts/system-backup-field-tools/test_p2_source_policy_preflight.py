import importlib.util
from pathlib import Path
from unittest.mock import Mock
import unittest

def load(name):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class SourcePolicyPreflightTest(unittest.TestCase):
    def test_missing_intent_stops_before_token_or_native_calls(self):
        c=load('continue-p2-nov14');a=load('assemble-p2-installation-candidate');site=Mock();native=Mock()
        for discovery in ({},{'SecretPolicy':{'protocol':'wrong','path':'private','sha256':'wrong'}}):
            with self.assertRaisesRegex(ValueError,'explicit original Secret backup policy'):
                c.refresh(A=a,L=None,H=None,R=native,N=None,D=None,F=None,T=None,site=site,package=None,parent=None,
                          original={'RedisSourcesVersion':'actual-v1','Materials':{'Discovery':discovery}},selected=None,
                          fresh=None,pod=None,desired=None,secret=None,plan=None,minted=None,observer=None,agent=None)
        self.assertEqual(site.mock_calls,[]);self.assertEqual(native.mock_calls,[])

if __name__=='__main__':unittest.main()
