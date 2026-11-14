import base64
import importlib.util
from contextlib import contextmanager, redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

class SourceFactsFlowTest(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name).resolve()
        self.M=load('produce-p2-source-facts');self.A=load('assemble-p2-installation-candidate');self.V=load('p2-source-provider-access')
        self.package=self.root/'package';self.package.mkdir();self.M.__file__=str(self.package/'produce-p2-source-facts.py')
        tool=self.package/'system-backup-source-registries';tool.write_bytes(b'native')
        self.A.retain(self.package/'BUILD_RECEIPT.json',{'Binaries':{tool.name:{'SHA256':self.A.sha(b'native')}}})
        self.C=NS(ROOT=self.root,SOURCE_JOURNAL=self.root/'source',MOUNT_JOURNAL=self.root/'mount',select_attempt=Mock())
        self.C.SOURCE_JOURNAL.mkdir();self.C.MOUNT_JOURNAL.mkdir()
        token=b'existing';observer={'Endpoint':'https://vault.'+self.A.NS+'.svc:8200','IdentityMode':'metadata-only','TokenFile':self.V.MOUNT+'/token','TokenSHA256':self.A.sha(token)}
        raw=self.A.encode(observer);secret={'immutable':True,'data':{'observer.json':base64.b64encode(raw).decode(),'token':base64.b64encode(token).decode()}}
        dep={'workload':{'Service':'vault'},'observer':{'File':self.V.MOUNT+'/observer.json','SHA256':self.A.sha(raw)}}
        core=self.A.retain(self.root/'core.json',{'provider_dependencies':[dep]});selection=self.A.retain(self.root/'selection.json',{'Controller':{'Pod':'controller','PodUID':'pod-uid'},'Connections':[]})
        self.selection=selection;self.C.live_source=Mock(return_value=self.A.obj(selection))
        self.A.retain(self.C.MOUNT_JOURNAL/'completed.json',{'Deployment':core,'SourceSelection':selection})
        self.A.retain(self.C.SOURCE_JOURNAL/'author.sent.private.json',{'Argv':['old','author','--plan-file','actual-plan','--definition-file','definition']})
        pod={'metadata':{'uid':'pod-uid'},'spec':{'volumes':[{'name':'provider-dependency-input','secret':{'secretName':'provider'}}]}}
        site=NS(get=lambda kind,name:pod if kind=='pod' else secret)
        self.dns=NS(probe=Mock());self.events=[];runner=object()
        @contextmanager
        def access(*args):
            self.events.append('transport-open')
            try:yield runner
            finally:self.events.append('transport-closed')
        self.V.access=access
        self.receipt={'Version':'original-source-registry-facts-receipt.v1','SelectionSHA256':selection['SHA256'],'PartsRegistry':{},'SourceWritersRegistry':{}}
        self.R=NS(once=Mock(return_value=self.receipt))
        modules={'continue-p2-nov14':self.C,'assemble-p2-installation-candidate':self.A,'load-p2-formal-vault':NS(Site=lambda *a:site),
                 'p2-source-dns':NS(SourceDNS=lambda *a:self.dns),'resume-p2-recovered-source':self.R,'p2-vault-local-forward':NS(),'p2-source-provider-access':self.V}
        self.M.load=lambda name:modules[name]
    def run_flow(self):
        with redirect_stdout(io.StringIO()):return self.M.run(8)
    def test_original_outputs_feed_native_with_private_transport(self):
        self.assertEqual(self.run_flow(),self.receipt)
        argv=self.R.once.call_args.args[-1]
        self.assertEqual(argv[1:],['produce-facts','--plan-file','actual-plan','--source-selection-file',self.selection['File'],'--source-selection-sha256',self.selection['SHA256']])
        self.assertEqual(self.events,['transport-open','transport-closed']);self.dns.probe.assert_called_once()
    def test_expired_source_stops_before_native(self):
        self.C.live_source.side_effect=ValueError('source expired')
        with self.assertRaisesRegex(ValueError,'source expired'):self.run_flow()
        self.R.once.assert_not_called();self.assertEqual(self.events,[])
    def test_native_failure_closes_transport_and_propagates(self):
        self.R.once.side_effect=ValueError('original failure retained')
        with self.assertRaisesRegex(ValueError,'original failure retained'):self.run_flow()
        self.assertEqual(self.events,['transport-open','transport-closed'])
    def test_wrong_receipt_cannot_report_success(self):
        self.R.once.return_value=dict(self.receipt,SelectionSHA256='foreign')
        with self.assertRaisesRegex(ValueError,'receipt differs'):self.run_flow()
        self.assertEqual(self.events,['transport-open','transport-closed'])

if __name__=='__main__':unittest.main()
