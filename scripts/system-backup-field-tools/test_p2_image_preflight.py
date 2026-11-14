import contextlib
import importlib.util
import io
import json
import re
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch, MagicMock

HERE=Path(__file__).parent
def load(name):
    s=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class ImageRetryTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.O=load('build-p2-controller-overlay');self.package=self.root/'package';self.package.mkdir();self.work=self.package/'image-work'
        binaries={}
        for name in self.O.TOOLS:
            raw=name.encode();(self.package/name).write_bytes(raw);binaries[name]={'SHA256':self.O.sha(raw)}
        (self.package/'BUILD_RECEIPT.json').write_text(json.dumps({'SourceRevision':'revision','Binaries':binaries}))
        self.calls=[];self.failure=None
        def run(argv,stdout,stderr,timeout):
            action=argv[4];self.calls.append(action);stdout.write(('step '+action).encode())
            if action=='export':Path(argv[5]).write_bytes(b'partial-or-complete-export')
            if self.failure==action:raise subprocess.TimeoutExpired(argv,timeout)
            return NS(returncode=0)
        def overlay(base,layer,out,tag):
            out.write_bytes(b'overlay')
            if self.failure=='overlay':raise ValueError('overlay interrupted')
            return 'a'*64
        def registry(receipt):
            if self.failure=='registry':raise ValueError('registry unavailable')
        for target,value in [('subprocess.run',run),('build_overlay',overlay),('registry_receipt',registry)]:
            # Patch module boundaries, retain real attempt/journal/receipt logic.
            obj=self.O.subprocess if target.startswith('subprocess.') else self.O
            p=patch.object(obj,target.split('.')[-1],side_effect=value);p.start();self.addCleanup(p.stop)
    def run_build(self):
        with contextlib.redirect_stdout(io.StringIO()):return self.O.build_image(self.package,self.work)
    def test_each_interrupted_stage_can_rerun_same_command(self):
        for stage in ('pull','export','overlay','import','push','registry'):
            with self.subTest(stage=stage):
                self.work=self.package/('image-work-'+stage);self.failure=stage
                with self.assertRaises((subprocess.TimeoutExpired,ValueError)):self.run_build()
                failed=next(self.work.glob('attempt-*'));self.assertTrue((failed/'failure.json').exists())
                before={p.name:p.read_bytes() for p in failed.iterdir() if p.is_file()}
                self.failure=None;self.run_build()
                self.assertEqual(before,{p.name:p.read_bytes() for p in failed.iterdir() if p.is_file()})
                self.assertTrue((self.work/'image.json').exists());self.assertEqual(len(list(self.work.glob('attempt-*'))),2)
    def test_legacy_interrupted_directory_is_preserved(self):
        self.work.mkdir();(self.work/'base.tar').write_bytes(b'legacy partial');self.run_build()
        self.assertEqual((self.work/'base.tar').read_bytes(),b'legacy partial')
    def test_completed_replay_only_rechecks_registry(self):
        self.run_build();count=len(self.calls);self.run_build();self.assertEqual(count,len(self.calls))
        self.failure='registry'
        with self.assertRaisesRegex(ValueError,'registry unavailable'):self.run_build()
        self.assertEqual(count,len(self.calls))
    def test_success_keeps_logs_but_removes_own_tar_files(self):
        self.run_build();attempt=next(self.work.glob('attempt-*'))
        self.assertTrue((attempt/'push.stdout.log').exists());self.assertFalse(list(attempt.glob('*.tar')))
    def test_package_mismatch_refuses_existing_receipt(self):
        self.run_build();receipt=json.loads((self.work/'image.json').read_bytes());receipt['SourceRevision']='foreign';(self.work/'image.json').write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError,'another package'):self.run_build()

class PreflightTest(unittest.TestCase):
    def setUp(self):
        fixture=load('test_p2_nov14_flow').FlowTest();fixture.setUp();self.addCleanup(fixture.doCleanups);self.f=fixture
        self.P=load('preflight-p2-team-continuation');fixture.modules['continue-p2-nov14']=fixture.M;fixture.modules['build-p2-controller-overlay']=load('build-p2-controller-overlay')
        self.P.load=lambda name:fixture.modules[name]
        build=fixture.A.decode((fixture.package/'BUILD_RECEIPT.json').read_bytes())
        build['LinkedBuildIdentity']={'Version':'p2-test','Commit':'a'*40}
        reader=patch.object(self.P,'binary_release_identity',return_value={'Version':'p2-test','Commit':'a'*40});reader.start();self.addCleanup(reader.stop)
        (fixture.package/'BUILD_RECEIPT.json').write_bytes(fixture.A.encode(build))
        fixture.A.CONTROLLER='controller';fixture.A.CONTROLLER_UID='depuid'
        plan=fixture.put(fixture.root/'plan.json',b'plan')
        (fixture.T.PARENT/'author.sent.private.json').write_text(json.dumps({'Argv':['old','author-initial-source-inputs','--plan-file',plan['File'],'--plan-sha256',plan['SHA256'],'--definition-file','old']}))
        self.owner_checks=[];self.space_checks=[]
        # Original owner is simulated; metadata identity is already covered by native-boundary tests.
        ownerpin=fixture.put(fixture.root/'owner-preflight.json',{'Endpoint':'https://vault','TokenFile':plan['File'],'TokenSHA256':plan['SHA256']})
        writer=fixture.A.obj(fixture.parent['VaultWriterSelection']);writer['PreAdoptionVaultDependencies'][0]['InstalledObserver']=ownerpin
        writerpin=fixture.put(fixture.root/'preflight-writer.json',writer);fixture.parent['VaultWriterSelection']=writerpin
        (fixture.T.PARENT/'completed.json').write_bytes(fixture.A.encode(fixture.parent))
        for obj,name,value in [(self.P.shutil,'which',lambda n:'/bin/'+n),(self.P,'owner_ttl',lambda *a:self.owner_checks.append(True)),(self.P,'registry_and_space',lambda *a:self.space_checks.append(True) or [])]:
            p=patch.object(obj,name,side_effect=value);p.start();self.addCleanup(p.stop)
    def run_preflight(self):
        with contextlib.redirect_stdout(io.StringIO()):return self.P.run(self.f.package,1)
    def test_success_reads_without_mint_or_deployment_update(self):
        report=self.run_preflight();self.assertTrue(report['ReadOnlyClusterChecks']);self.assertFalse(report['ImageBuildStarted'])
        self.assertEqual(self.f.native_calls,[]);self.assertNotIn('patch',self.f.events);self.assertTrue(self.owner_checks and self.space_checks)
        self.assertFalse(self.f.journal.exists())
    def test_dev_build_refused_before_remote_work(self):
        p=self.f.package/'BUILD_RECEIPT.json';build=self.f.A.decode(p.read_bytes());build['LinkedBuildIdentity']['Version']='dev';p.write_bytes(self.f.A.encode(build))
        with self.assertRaisesRegex(ValueError,'native release identity missing'):self.run_preflight()
        self.assertFalse(self.owner_checks or self.space_checks or self.f.native_calls)
    def test_mixed_linked_commits_refused_before_remote_work(self):
        p=self.f.package/'BUILD_RECEIPT.json';build=self.f.A.decode(p.read_bytes());build['LinkedBuildIdentity']['Commit']='b'*40;p.write_bytes(self.f.A.encode(build))
        with self.assertRaisesRegex(ValueError,'native linked identity differs'):self.run_preflight()
        self.assertFalse(self.owner_checks or self.space_checks or self.f.native_calls)
    def test_expired_certificate_stops_before_vault_or_registry(self):
        self.f.until=(self.f.now-self.f.N.dt.timedelta(seconds=1)).isoformat()
        with self.assertRaisesRegex(ValueError,'certificate has less'):self.run_preflight()
        self.assertFalse(self.owner_checks or self.space_checks)
    def test_missing_required_file_stops_before_registry(self):
        (self.f.root/'plan.json').unlink()
        with self.assertRaises((ValueError,FileNotFoundError)):self.run_preflight()
        self.assertFalse(self.space_checks)
    def test_expired_vault_stops_before_registry(self):
        self.P.owner_ttl.side_effect=ValueError('owner expired')
        with self.assertRaisesRegex(ValueError,'owner expired'):self.run_preflight()
        self.assertFalse(self.space_checks)
    def test_source_dns_failure_stops_before_image_and_issuance(self):
        def refused():raise ValueError('source DNS failed')
        self.f.modules['p2-source-dns']=NS(SourceDNS=lambda *a:NS(probe=refused))
        with self.assertRaisesRegex(ValueError,'source DNS failed'):self.run_preflight()
        self.assertFalse(self.owner_checks or self.space_checks)
    def test_original_controller_drift_stops_before_vault_and_image(self):
        self.f.H.current_controller=lambda *a:(_ for _ in ()).throw(ValueError('controller changed'))
        with self.assertRaisesRegex(ValueError,'controller changed'):self.run_preflight()
        self.assertFalse(self.owner_checks or self.space_checks)
    def test_registry_failure_stops_without_image_or_mutation(self):
        self.P.registry_and_space.side_effect=ValueError('registry unavailable')
        with self.assertRaisesRegex(ValueError,'registry unavailable'):self.run_preflight()
        self.assertEqual(self.f.native_calls,[]);self.assertNotIn('patch',self.f.events)
    def test_entry_orders_preflight_before_build_and_passes_attempt(self):
        script=(HERE/'run-p2-team-continuation.sh').read_text()
        self.assertLess(script.index('preflight-p2-team-continuation.py'),script.index('build-p2-controller-overlay.py'))
        self.assertIn('preflight-p2-team-continuation.py "$@"',script)

class PrivateExecutableTest(unittest.TestCase):
    def test_shell_executable_mode_passes_actual_posix_pin_policy(self):
        A=load('assemble-p2-installation-candidate');raw=b'executable';file=MagicMock()
        file.is_absolute.return_value=True;file.is_symlink.return_value=False;file.is_file.return_value=True;file.resolve.return_value=file;file.read_bytes.return_value=raw
        mode=int(re.search(r'chmod ([0-7]+)',(HERE/'run-p2-team-continuation.sh').read_text()).group(1),8)
        with patch.object(A,'os',NS(name='posix')),patch.object(A,'Path',return_value=file):
            file.stat.return_value=NS(st_mode=mode,st_size=len(raw))
            self.assertEqual(A.read({'File':'/tool','SHA256':A.sha(raw)}),raw)
            file.stat.return_value.st_mode=0o755
            with self.assertRaisesRegex(ValueError,'private runtime input'):A.read({'File':'/tool','SHA256':A.sha(raw)})

class SpaceTest(unittest.TestCase):
    def test_owner_zero_ttl_only_accepts_nonexpiring_identity(self):
        P=load('preflight-p2-team-continuation');A=load('assemble-p2-installation-candidate')
        until=P.dt.datetime.now(P.dt.timezone.utc)+P.dt.timedelta(minutes=45)
        P.owner_covers_window(A,{'ttl':0,'creation_ttl':0,'expire_time':None},until)
        for data in ({'ttl':0,'creation_ttl':3600,'expire_time':'now'},{'ttl':1},{'ttl':True}):
            with self.assertRaises(ValueError):P.owner_covers_window(A,data,until)
    def test_shared_filesystem_budgets_are_summed_and_shortage_refused(self):
        P=load('preflight-p2-team-continuation');A=load('assemble-p2-installation-candidate')
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);(path/'tool').write_bytes(b'tool')
            response=NS(status=200);opener=contextlib.nullcontext(response)
            with patch.object(P.urllib.request,'urlopen',return_value=opener),patch.object(P,'registry_manifest',return_value={'layers':[{'size':100}]}),patch.object(P.shutil,'disk_usage',return_value=NS(free=5<<30)):
                with self.assertRaisesRegex(ValueError,'insufficient working disk'):P.registry_and_space(A,NS(BASE='x@sha256:abc',TOOLS=['tool']),path,{},path,path)

if __name__=='__main__':unittest.main()
