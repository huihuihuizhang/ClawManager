"""Offline entry-point integration; fake Kubernetes/Vault/native boundaries, real pins/journals/plans."""
import base64
import contextlib
import copy
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent
def load(name):
    s=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class FlowTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.M=load('continue-p2-nov14');self.A=load('assemble-p2-installation-candidate');self.P=load('p2-nov14-delivery')
        self.L=load('load-p2-formal-vault');self.H=load('prepare-p2-longhorn-provider-loaded');self.R=load('resume-p2-recovered-source')
        self.N=load('renew-p2-source-preparation');self.T=load('resume-p2-tenant-team-source');self.S=load('prepare-p2-longhorn-source')
        self.journal=self.root/'p2-team-continuation-20261114';self.mirror=self.root/'mirror';self.mirror.mkdir();self.package=self.root/'package';self.package.mkdir()
        self.M.ROOT=self.root;self.M.JOURNAL=self.journal;self.M.MIRROR=self.mirror
        self.events=[];self.fail=None;self.native_calls=[];self.created=False
        self.now=dt.datetime.now(dt.timezone.utc);self.until=(self.now+dt.timedelta(hours=4)).isoformat()
        def put(path,value):path.parent.mkdir(parents=True,exist_ok=True);return self.A.retain(path,value)
        self.put=put
        self.binaries={n:{'SHA256':self.A.sha(n.encode())} for n in ('system-backup-source-registries','system-backup-first-install-materials','system-backup-v2-controller')}
        for n in self.binaries:put(self.package/n,n.encode())
        put(self.package/'BUILD_RECEIPT.json',{'SourceRevision':'rev','Binaries':self.binaries});put(self.package/'SOURCE_REVISION',b'rev')
        self.image='10.130.14.23:5000/clawmanager@sha256:'+'a'*64
        image=put(self.root/'image.json',{'Version':'p2-controller-image.v1','SourceRevision':'rev','Binaries':self.binaries,'Image':self.image})
        self.args=NS(image_receipt=image['File'],image_sha256=image['SHA256'],source_attempt=1)
        oldtoken=b'old';self.oldobs={'IdentityMode':'metadata-only','TokenFile':'old','TokenSHA256':self.A.sha(oldtoken),'ObserverPolicy':'meta','Endpoint':'https://vault','CAPEM':'ca'}
        raw=self.P.encoded(self.oldobs)
        self.oldsecret={'metadata':{'name':'old','namespace':self.A.NS},'immutable':True,'data':{'observer.json':base64.b64encode(raw).decode(),'token':base64.b64encode(oldtoken).decode()}}
        self.secrets={'old':self.oldsecret};self.workload={'Service':'vault','DeploymentUID':'vaultuid'}
        podspec={'serviceAccountName':'controller-sa','volumes':[{'name':'provider-dependency-input','secret':{'secretName':'old'}}],
            'initContainers':[{'name':'provider-dependency-install','image':'old','command':['/usr/local/bin/system-backup-source-registries'],'args':['install-provider-files','--observer-sha256',self.A.sha(raw),'--token-sha256',self.A.sha(oldtoken)]}],
            'containers':[{'name':'controller','image':'old'},{'name':'installation-owner','image':'old'}]}
        self.dep={'metadata':{'name':'controller','namespace':self.A.NS,'uid':'depuid','resourceVersion':'1','generation':1},'spec':{'replicas':1,'selector':{'matchLabels':{'app':'controller'}},'template':{'spec':podspec}},'status':{'observedGeneration':1,'readyReplicas':1,'updatedReplicas':1}}
        self.ref={'Deployment':'controller','DeploymentUID':'depuid','Namespace':self.A.NS,'Pod':'oldpod','PodUID':'olduid','ReplicaSet':'oldrs','ReplicaSetUID':'oldrsuid','ServiceAccount':'controller-sa','ServiceAccountUID':'sauid'}
        self.T.PARENT=self.root/'parent';self.T.PARENT.mkdir();self.L.PARENT=self.root/'formal';self.H.PARENT=self.root/'loaded'
        self.L.RECEIPT_SHA=put(self.L.PARENT/'receipt.private.json',{'Workload':self.workload,'SecretManifest':put(self.root/'old-secret.json',self.oldsecret)})['SHA256']
        put(self.H.PARENT/'delivery-plan.private.json',{'DesiredSpec':put(self.root/'old-spec.json',self.dep['spec'])})
        conn={'Purpose':'source_api','Account':'sourceuid','Endpoint':'https://api','Credential':put(self.root/'old.jwt',b'old')}
        oldout=self.mirror/'old';oldout.mkdir()
        observer={k:k for k in ('CAFile','CASHA256','CertificateFile','CertificateSHA256','KeyFile','KeySHA256','Endpoints')}
        core={'profile_file':str(oldout/'execution-profile.json'),'capture_modules':{'path':str(oldout/'capture-materials.json')},'provider_dependencies':[{'workload':self.workload,'observer':{}}],'runtime_sources':{'shared_runtime_observer':observer}}
        definition={'Version':'original-initial-source-author-inputs.v1','Controller':self.ref,'Connections':[conn],'Deployment':core,'Materials':{'DeploymentConfigSHA256':'','CaptureGrantSHA256':'','Discovery':{'SourceAPI':{'token_file':conn['Credential']['File']},'SourceAPITokenSHA256':conn['Credential']['SHA256']}}}
        selected={'Controller':self.ref,'Connections':[conn]}
        self.parent={'Definition':put(self.T.PARENT/'definition.json',definition),'SourceSelection':put(oldout/'source-selection.json',selected),'Receipt':put(self.T.PARENT/'receipt.json',{'Version':'parent'}),'GrantsIssued':False,
            'SourceAPI':put(self.T.PARENT/'api.json',{'connection':conn,'service_account':'source-sa','service_account_uid':'sourceuid'}),
            'VaultWriterSelection':put(self.T.PARENT/'writer.json',{'PreAdoptionVaultDependencies':[{'Workload':self.workload,'InstalledObserver':put(self.T.PARENT/'owner.json',{'Endpoint':'https://vault'})}]})}
        for name,key in [('RECEIPT_SHA','Receipt'),('DEFINITION_SHA','Definition'),('SELECTION_SHA','SourceSelection')]:setattr(self.T,name,self.parent[key]['SHA256'])
        put(self.T.PARENT/'completed.json',self.parent);put(self.T.PARENT/'author.sent.private.json',{'Argv':['oldbin','author-initial-source-inputs','--plan-file','plan','--definition-file','old','--definition-sha256','old','--output-directory','old']})
        real_obj=self.A.obj
        self.A.obj=lambda pin: {'NotAfter':self.until} if '/renewal-20261113/' in pin['File'].replace('\\','/') else real_obj(pin)
        self.L.Site=lambda directory,A:Site(self,directory)
        self.L.verify_secret=lambda actual,wanted:self.assertEqual(actual,wanted)
        self.L.verify_metadata=lambda *args:self.events.append('metadata-verified')
        self.H.current_controller=lambda *args:self.pod()
        self.R.verify_app=lambda *args:{}
        class Forward:
            def __init__(s,*a):pass
            def __enter__(s):return '127.0.0.1:12345'
            def __exit__(s,*a):pass
        self.modules={'assemble-p2-installation-candidate':self.A,'load-p2-formal-vault':self.L,'prepare-p2-longhorn-provider-loaded':self.H,'resume-p2-recovered-source':self.R,'renew-p2-source-preparation':self.N,'resume-p2-tenant-team-source':self.T,'p2-nov14-delivery':self.P,'p2-vault-local-forward':NS(LocalForward=Forward),'p2-source-dns':NS(SourceDNS=lambda *a:DNS(self)),
            'prepare-p2-longhorn-source':self.S,'prepare-p2-team-attachment':NS(prepare=self.attach)}
        self.M.load=lambda name:self.modules[name]
        self.M.private_journal=lambda A:self.journal.mkdir(exist_ok=True)
    def pod(self):
        new=self.dep['spec']['template']['spec']['containers'][0]['image']==self.image
        return {'metadata':{'name':'newpod' if new else 'oldpod','namespace':self.A.NS,'uid':'newuid' if new else 'olduid','ownerReferences':[{'controller':True,'kind':'ReplicaSet','name':'newrs','uid':'rsuid'}]},'spec':copy.deepcopy(self.dep['spec']['template']['spec']),'status':{'phase':'Running','containerStatuses':[{'ready':True},{'ready':True}]}}
    def attach(self,A,L,core,selected,journal):
        self.events.append('attachment');self.created=True
        return [{'TeamID':1,'Namespace':'tenant','Pod':'attachment','Image':self.image}]
    def run_flow(self):
        with contextlib.redirect_stdout(io.StringIO()):self.M.run(self.args,self.package)
    def native(self,argv):
        action=argv[1];self.native_calls.append(action)
        if self.fail==action:raise TimeoutError('simulated native outcome unknown')
        val=lambda flag:argv[argv.index(flag)+1]
        out=Path(val('--output-directory'))
        if action=='issue-provider-metadata':
            token=self.put(out/'token',b'new');obs={**self.oldobs,'TokenFile':token['File'],'TokenSHA256':token['SHA256']}
            return {'Version':'installed-vault-metadata-materials.v1','Observer':self.put(out/'observer.json',obs),'Workload':self.workload}
        if action=='author-initial-source-inputs':
            definition=self.A.obj({'File':val('--definition-file'),'SHA256':val('--definition-sha256')})
            self.assertEqual(definition['Controller']['Pod'],'newpod');self.assertNotEqual(definition['Connections'][0]['Credential'],self.A.obj(self.parent['SourceAPI'])['connection']['Credential'])
            core=self.put(out/'deployment.json',definition['Deployment']);material=self.put(out/'materials.json',{**definition['Materials'],'DeploymentConfigSHA256':core['SHA256']})
            selected={k:definition[k] for k in ('Controller','Connections','NotBefore','Until')};selected.update(Deployment=core,MaterialsTemplate=material,PartsFile=str(out/'parts.json'),SourceWritersFile=str(out/'writers.json'),RedisSourcesFile=str(out/'redis.json'))
            if self.fail=='wrong-source-token':selected['Connections']=[]
            return {'Version':'original-initial-source-inputs-authored.v1','GrantsIssued':False,'BackupReady':False,'Deployment':core,'SourceSelection':self.put(out/'source-selection.json',selected)}
        self.assertEqual(action,'prepare-mount-materials');self.assertTrue(self.created)
        selected=self.A.obj({'File':val('--source-selection-file'),'SHA256':val('--source-selection-sha256')});layout=self.A.obj({'File':val('--mount-layouts-file'),'SHA256':val('--mount-layouts-sha256')})
        self.assertEqual(layout['TeamAttachments'][0]['TeamID'],1)
        hold=self.put(out/'hold.json',{'hold':'native'});core=self.A.obj(selected['Deployment']);observer=copy.deepcopy(core['runtime_sources']['shared_runtime_observer']);observer.update(WholeNodeEndpoints=None,Nodes=None)
        core['runtime_sources']['longhorn_hold']={'Observer':observer,'Materials':[hold]};corepin=self.put(out/'deployment.json',core)
        mat=self.A.obj(selected['MaterialsTemplate']);mat['DeploymentConfigSHA256']=corepin['SHA256'];matpin=self.put(out/'material.json',mat)
        successor={**selected,'Deployment':corepin,'MaterialsTemplate':matpin}
        return {'Version':'original-instance-mount-materials-receipt.v1','SelectionSHA256':val('--source-selection-sha256'),'LayoutSelectionSHA256':val('--mount-layouts-sha256'),'Deployment':corepin,'MaterialsTemplate':matpin,'SourceSelection':self.put(out/'selection.json',successor),'LonghornHoldMaterials':hold}
    def test_full_entry_and_live_repeat_do_not_reissue(self):
        self.run_flow();self.run_flow()
        self.assertEqual(self.native_calls,['issue-provider-metadata','author-initial-source-inputs','prepare-mount-materials'])
        self.assertTrue((self.M.MOUNT_JOURNAL/'completed.json').exists())
    def test_rollout_failure_resumes_from_live_deployment(self):
        self.fail='rollout'
        with self.assertRaisesRegex(ValueError,'rollout'):self.run_flow()
        self.fail=None;self.run_flow()
        self.assertEqual(self.native_calls.count('issue-provider-metadata'),1)
    def test_successful_native_receipts_resume_missing_summaries(self):
        self.run_flow();(self.M.SOURCE_JOURNAL/'completed.json').unlink();(self.M.MOUNT_JOURNAL/'completed.json').unlink()
        self.run_flow();self.assertEqual(len(self.native_calls),3)
    def test_unknown_native_outcome_never_reissued(self):
        self.fail='author-initial-source-inputs'
        with self.assertRaises(TimeoutError):self.run_flow()
        self.fail=None
        with self.assertRaisesRegex(ValueError,'without successful receipt'):self.run_flow()
        self.assertEqual(self.native_calls.count('author-initial-source-inputs'),1)
    def expire(self):
        # Simulate authentic materials that were valid when issued, then advance clock.
        future=self.now+dt.timedelta(hours=1)
        class Future(dt.datetime):
            @classmethod
            def now(cls,tz=None):return future
        return patch.object(self.M.dt,'datetime',Future)
    def test_expired_success_never_reports_ready(self):
        self.run_flow()
        with self.expire(),self.assertRaisesRegex(ValueError,'source expired'):self.run_flow()
        self.assertEqual(len(self.native_calls),3)
    def test_expired_source_uses_explicit_separate_attempt(self):
        self.run_flow();self.args.source_attempt=2
        with self.expire():self.run_flow()
        self.assertEqual(self.native_calls.count('issue-provider-metadata'),1)
        self.assertEqual(self.native_calls.count('author-initial-source-inputs'),2)
        self.assertTrue((self.journal/'source/completed.json').exists());self.assertTrue((self.journal/'source-2/completed.json').exists())
    def test_bad_native_output_cannot_feed_mount(self):
        self.fail='wrong-source-token'
        with self.assertRaisesRegex(ValueError,'native refreshed source differs'):self.run_flow()
        self.assertFalse(self.created)
    def test_expired_success_with_missing_summaries_can_start_successor(self):
        self.run_flow();(self.M.SOURCE_JOURNAL/'completed.json').unlink();(self.M.MOUNT_JOURNAL/'completed.json').unlink();self.args.source_attempt=2
        with self.expire():self.run_flow()
        self.assertEqual(len(self.native_calls),5)
    def test_lost_secret_create_response_is_observed_not_recreated(self):
        self.fail='secret-create'
        with self.assertRaises(TimeoutError):self.run_flow()
        self.fail=None;self.run_flow();self.assertEqual(self.native_calls.count('issue-provider-metadata'),1)
    def test_ten_minute_boundary_is_not_reusable(self):
        self.run_flow();done=self.A.decode((self.M.SOURCE_JOURNAL/'completed.json').read_bytes())
        boundary=dt.datetime.fromisoformat(done['Until'].replace('Z','+00:00'))-dt.timedelta(minutes=10)
        with self.assertRaisesRegex(ValueError,'source expired'):self.M.live_source(self.A,done,boundary)
    def test_collected_source_cannot_start_new_attempt(self):
        self.run_flow();done=self.A.decode((self.M.SOURCE_JOURNAL/'completed.json').read_bytes())
        selected=self.A.obj(done['SourceSelection']);Path(selected['PartsFile']).write_bytes(b'collected')
        self.args.source_attempt=2
        with self.expire(),self.assertRaisesRegex(ValueError,'facts already produced'):self.run_flow()
        self.assertEqual(len(self.native_calls),3)
    def test_collected_live_source_cannot_report_prepared(self):
        self.run_flow();done=self.A.decode((self.M.SOURCE_JOURNAL/'completed.json').read_bytes())
        Path(self.A.obj(done['SourceSelection'])['PartsFile']).write_bytes(b'collected')
        with self.assertRaisesRegex(ValueError,'facts already produced'):self.run_flow()
        self.assertEqual(len(self.native_calls),3)
    def test_expired_unissued_draft_can_continue_in_new_attempt(self):
        original_probe=DNS.probe
        def fail_source(dns):
            if (self.M.SOURCE_JOURNAL/'definition.private.json').exists():raise ValueError('DNS failed before source invocation')
        with patch.object(DNS,'probe',fail_source):
            with self.assertRaisesRegex(ValueError,'DNS failed'):self.run_flow()
        self.assertFalse((self.M.SOURCE_JOURNAL/'author.sent.private.json').exists())
        self.args.source_attempt=2
        with self.expire():self.run_flow()
        self.assertEqual(self.native_calls.count('author-initial-source-inputs'),1)
    def test_successor_refuses_unexpired_source(self):
        self.run_flow();self.args.source_attempt=2
        with self.assertRaisesRegex(ValueError,'must expire'):self.run_flow()

class DNS:
    def __init__(self,flow):self.f=flow
    def probe(self):pass
    def run(self,argv,stdout,stderr,timeout):stdout.write(self.f.A.encode(self.f.native(argv)));return NS(returncode=0)

class Site:
    def __init__(self,f,directory):self.f=f;self.directory=directory
    def get(self,kind,name):
        f=self.f
        if kind=='deployment':return copy.deepcopy(f.dep)
        if kind=='secret':return f.secrets[name]
        if kind=='replicaset':return {'metadata':{'name':'newrs','uid':'rsuid','ownerReferences':[{'controller':True,'kind':'Deployment','uid':'depuid'}]}}
        if kind=='serviceaccount':return {'metadata':{'uid':'sourceuid' if name=='source-sa' else 'sauid'}}
        if kind=='volumesnapshotclass':return {'metadata':{'name':name,'uid':'f28ccd84-5689-4c56-a25c-5ba1b1d2e24e'},'driver':'driver.longhorn.io','deletionPolicy':'Delete','parameters':{'type':'snap'}}
        if kind=='storageclass':return {'metadata':{'name':name,'uid':'9086f7e9-1213-485e-9ec2-3e5de93f908a'},'provisioner':'driver.longhorn.io','parameters':{'fsType':'ext4'},'volumeBindingMode':'Immediate','reclaimPolicy':'Delete'}
        raise AssertionError((kind,name))
    def send(self,label,args,body):
        self.f.A.need(not (self.directory/(label+'.sent.private.json')).exists(),'already sent; reconcile')
        self.f.A.retain(self.directory/(label+'.sent.private.json'),{'Argv':args,'InputSHA256':self.f.A.sha(body)})
        return self.call(args,body)
    def call(self,args,body=None,timeout=None):
        f=self.f
        if args[0]=='patch':
            patch=json.loads(body);f.events.append('patch');f.assertEqual(patch[2]['value'],f.dep['spec'])
            result=copy.deepcopy(f.dep);result['spec']=patch[-1]['value']
            if '--dry-run=server' not in args:f.dep=result
            return f.A.encode(result)
        if args[:2]==['create','-f']:
            secret=json.loads(body);f.secrets[secret['metadata']['name']]=secret
            if f.fail=='secret-create':raise TimeoutError('lost secret create response')
            return f.A.encode(secret)
        if args[:2]==['get','secret']:return f.A.encode(f.secrets[args[2]]) if args[2] in f.secrets else b''
        if args[:2]==['get','pods']:return f.A.encode({'items':[f.pod()]})
        if args[0]=='rollout':
            if f.fail=='rollout':raise ValueError('simulated rollout timeout')
            return b''
        if args[:2]==['create','--raw']:
            if args[2].endswith('/token'):return f.A.encode({'status':{'token':'fresh','expirationTimestamp':f.until}})
            return f.A.encode({'status':{'authenticated':True,'user':{'username':'system:serviceaccount:'+f.A.NS+':source-sa','uid':'sourceuid'}}})
        if args[0]=='exec':
            name=Path(args[-1]).name
            if name in f.binaries:return (f.binaries[name]['SHA256']+'  '+args[-1]).encode()
            secret=next(v for k,v in f.secrets.items() if k!='old');digest=f.A.sha(base64.b64decode(secret['data'][name]))
            return ('600 65532\n'+digest+'  '+args[-1]).encode()
        raise AssertionError(args)

if __name__=='__main__':unittest.main()
