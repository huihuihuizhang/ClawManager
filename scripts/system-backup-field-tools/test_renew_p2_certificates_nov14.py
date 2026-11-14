import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

def load(name):
 s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class RenewalTest(unittest.TestCase):
 def setUp(self):
  self.M=load('renew-p2-certificates-nov14');self.A=load('assemble-p2-installation-candidate');self.R=load('resume-p2-recovered-source')
 def test_argv_changes_only_definition_and_output(self):
  old=['native','--plan-file','plan','--local-admin-password-file','password','--definition-file','old','--definition-sha256','oldsha','--output-directory','oldout']
  result=self.M.replaced_argv(self.A,old,{'File':'new','SHA256':'newsha'},'newout')
  self.assertEqual(result[:5],old[:5]);self.assertEqual(old[-1],'oldout');self.assertEqual(result[-1],'newout')
 def test_ambiguous_argv_refused(self):
  with self.assertRaises(ValueError):self.M.replaced_argv(self.A,['native','--definition-file','a','--definition-file','b'],{'File':'new','SHA256':'sha'},'out')
 def test_successful_native_result_is_reused_without_issuing_again(self):
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder).resolve();self.M.NEW=root/'new';self.M.NEW.mkdir()
   binary=root/'native';binary.write_bytes(b'native');(root/'SHA256SUMS').write_text(self.A.sha(b'native')+'  native\n')
   intent={'Argv':[str(binary),'--definition-file','old','--definition-sha256','oldsha','--output-directory','oldout']}
   def native(argv,stdout,stderr,timeout):stdout.write(b'{"Version":"fixture"}');return NS(returncode=0)
   with patch.object(self.M.subprocess,'run',side_effect=native) as run:
    pin,_=self.M.issue(self.A,self.R,'observer',intent,{'definition':1})
    again,_=self.M.issue(self.A,self.R,'observer',intent,{'definition':1})
    self.assertEqual(pin,again);self.assertEqual(run.call_count,1)
 def test_unknown_materials_refuse_new_native_call(self):
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder).resolve();self.M.NEW=root/'new';directory=self.M.NEW/'observer';directory.mkdir(parents=True);(directory/'materials').mkdir();(directory/'native.sent.private.json').write_bytes(b'{}')
   binary=root/'native';binary.write_bytes(b'native');(root/'SHA256SUMS').write_text(self.A.sha(b'native')+'  native\n')
   intent={'Argv':[str(binary),'--definition-file','old','--definition-sha256','oldsha','--output-directory','oldout']}
   with patch.object(self.M.subprocess,'run') as run:
    with self.assertRaisesRegex(ValueError,'unknown native issuance'):self.M.issue(self.A,self.R,'observer',intent,{})
    run.assert_not_called()

if __name__=='__main__':unittest.main()
