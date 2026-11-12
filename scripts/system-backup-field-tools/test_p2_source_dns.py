"""Resolver input/argv checks only; never simulates real DNS or native IO."""
import importlib.util
from pathlib import Path
import unittest

s=importlib.util.spec_from_file_location('source_dns',Path(__file__).with_name('p2-source-dns.py'))
D=importlib.util.module_from_spec(s);s.loader.exec_module(D)

class SourceDNSChecks(unittest.TestCase):
 def service(self):return {'metadata':{'name':'kube-dns','namespace':'kube-system','uid':'fixture-dns'},'spec':{'clusterIP':'10.96.0.10','clusterIPs':['10.96.0.10']}}
 def resolver(self):return ('nameserver 10.96.0.10\nsearch '+D.NS+'.svc.cluster.local svc.cluster.local cluster.local\noptions ndots:5\n').encode()
 def test_actual_namespace_search_and_selected_dns_required(self):
  self.assertEqual(D.validate_resolver(self.resolver(),self.service())['DNSServiceUID'],'fixture-dns')
  for raw in [self.resolver().replace(b'10.96.0.10',b'8.8.8.8'),self.resolver().replace(D.NS.encode(),b'foreign'),self.resolver()+b'nameserver 1.1.1.1\n',self.resolver()+b'unknown-directive value\n']:
   with self.assertRaises(ValueError):D.validate_resolver(raw,self.service())
 def test_native_arguments_remain_literal_in_private_namespace_command(self):
  argv=['/fixture/native','--file','/fixture/space name; untouched']
  selected=D.command(Path('/fixture/controller.resolv.conf'),argv)
  self.assertEqual(selected[:5],['unshare','--mount','--propagation','private','--'])
  self.assertEqual(selected[-len(argv):],argv)
  self.assertIn('exec "$@"',selected[7])
  self.assertIn('mount -o remount,bind,ro',selected[7])
 def test_invalid_literal_arguments_refuse_before_dispatch(self):
  for argv in [[],['/fixture/native',None],['/fixture/native','bad\x00value']]:
   with self.assertRaises(ValueError):D.command(Path('/fixture/resolv.conf'),argv)

if __name__=='__main__':unittest.main()
