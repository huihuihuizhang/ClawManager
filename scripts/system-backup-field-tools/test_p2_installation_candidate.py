import copy
import ast
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parent
A = load('p2_candidate', ROOT / 'assemble-p2-installation-candidate.py')
R = load('p2_native', ROOT / 'continue-p2-native-candidate.py')
C = load('p2_complete', ROOT.parent / 'system-backup-initial-complete-inputs.py')
V = load('p2_vault', ROOT / 'prepare-p2-vault-owner.py')
NOW = datetime.datetime(2026,11,11,10,tzinfo=datetime.timezone.utc)


class CandidateIntegration(unittest.TestCase):
    def setUp(self):
        # Mandatory D scratch; no fallback to the user's C TEMP.
        scratch = Path(os.environ['P2_TEST_DIRECTORY'])
        self.assertEqual(scratch.drive.lower(), 'd:')
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def save(self, name, value):
        return A.retain(self.root / name, value)

    def fixture(self):
        ca = self.save('ca.pem', b'fixture public CA only')
        creds = [self.save('credential-'+str(i), ('test-only-'+str(i)).encode()) for i in range(5)]
        def connection(purpose, index):
            return dict(Purpose=purpose, Endpoint='https://test-only', Account='test-account', ServerUUID='', Database='', CA=ca,
                        Credential=creds[index], IdentitySHA256='', ScopeSHA256='')
        policy = {'fixture':'real native policy shape is validated by Go'}
        policy_pin = self.save('policy.json', policy)
        keeper = {'Native':{'Policy':policy}, 'ReaderCredential':creds[3]}
        keeper_pin = self.save('keeper.json',keeper)
        writer = self.save('writer.json', {'Participants':[]})
        sql = self.save('sql.json', dict(Address='mysql.test:3306', Database='testdb', ServerUUID='actual-uuid',
            Accounts=[dict(Role='control_sql',User='control',Host='original-host'),dict(Role='source',User='reader',Host='original-host')]))
        objects = dict(CredentialFile=creds[2]['File'],CredentialSHA256=creds[2]['SHA256'])
        minio = self.save('minio.json',dict(Version='validation-p2-minio-source-data.v1',Connection=connection('source_objects',2),MaterialsObjectsData=objects))
        redis = self.save('redis.json',dict(Version='validation-p2-redis-source-data.v1',Connection=connection('source_redis',3),
            KeeperSelection=keeper_pin, Policy=policy_pin, WriterSelection=writer,
            NativeReceipt=dict(State='native_tls_and_accounts_read_back_not_a_hold',WriterSelection=writer)))
        api = self.save('api.json',dict(connection=connection('source_api',1),token_expires_unix=NOW.timestamp()+7200))
        forward = self.save('forward.public',b'F'*32)
        source = self.save('source.public',b'S'*32)
        record = dict(Issuers={'forward_execution':{'PublicKey':forward}})
        issuers = self.save('issuers.json',{'Record':__import__('base64').b64encode(A.encode(record)).decode(),'Signature':'fixture-only'})
        cert,key = self.save('client.pem', b'fixture cert'), self.save('client.key', b'fixture key')
        observer = self.save('observer.json',dict(NotBefore='2026-11-11T09:00:00Z',NotAfter='2026-11-11T12:00:00Z',CA=ca,ClientCertificate=cert,ClientKey=key))
        shared = {name+suffix:pin[k] for name,pin in [('CA',ca),('Certificate',cert),('Key',key)] for suffix,k in [('File','File'),('SHA256','SHA256')]}
        core = dict(namespace=A.NS,controller_owner=A.CONTROLLER_UID,source_database='testdb',source_server_uuid='actual-uuid',source_dsn_file=creds[4]['File'],
            runtime_sources=dict(shared_runtime_protocol='shared-container-freeze.v1',lease_participants=[],shared_runtime_observer=shared),
            redis_read_keepers=[keeper],forward_grant=dict(public_key_base64=__import__('base64').b64encode(b'F'*32).decode()),recovery_grant=dict(public_key_base64=__import__('base64').b64encode(b'F'*32).decode()))
        materials = dict(DeploymentConfigSHA256='',CaptureGrantSHA256='',Objects=objects,
            Redis=dict(CredentialFile=creds[3]['File'],CredentialSHA256=creds[3]['SHA256']),
            Discovery=dict(Redis=policy,SourceAPITokenSHA256=creds[1]['SHA256'],SourceAPIServiceAccountUID='test-account',
                SourceAPI=dict(TokenFile=creds[1]['File']),Issuer=__import__('base64').b64encode(b'S'*32).decode()))
        config = self.save('configuration.json',dict(Version='original-initial-source-author-inputs.v1',Deployment=core,Materials=materials,Profile={},
            Controller=dict(Deployment=A.CONTROLLER,DeploymentUID=A.CONTROLLER_UID),Until='2026-11-11T11:00:00Z'))
        return dict(Version='p2-installation-assembly-inputs.v1',ConfigurationData=config,MinIO=minio,Redis=redis,SourceAPI=api,
            SQLOperation=sql,ControlDSN=creds[0],SourceDSN=creds[4],DatabaseCA=ca,RuntimeIssuers=issuers,SourceIssuerPublic=source,ObserverReceipt=observer)

    def test_five_original_connections_exact_bytes_and_distinct_purpose_keys(self):
        inputs = self.fixture()
        output = A.assemble(inputs,NOW)
        self.assertEqual([c['Purpose'] for c in output['Connections']],A.PURPOSES)
        self.assertEqual(output['Connections'][0]['Account'],'control@original-host')
        self.assertEqual(output['Connections'][-1]['Account'],'reader@original-host')
        self.assertEqual(output['Deployment']['runtime_sources']['lease_participants'],[])
        Path(inputs['SourceDSN']['File']).write_bytes(b'new unrelated credential')
        with self.assertRaisesRegex(ValueError,'original bytes changed'):
            A.assemble(inputs,NOW)

    def test_expired_observer_cannot_be_carried_from_offline_snapshot(self):
        inputs=self.fixture()
        with self.assertRaisesRegex(ValueError,'validity'):
            A.assemble(inputs,NOW+datetime.timedelta(hours=4))

    def test_line_endings_are_not_canonicalized_for_native_pins(self):
        pin=self.save('signed.json',b'{"a":1}\r\n')
        self.assertEqual(A.read(pin),b'{"a":1}\r\n')
        Path(pin['File']).write_bytes(b'{"a":1}\n')
        with self.assertRaises(ValueError): A.read(pin)
        with self.assertRaises(ValueError): A.decode(b'{"a":1,"a":2}')

    def successor(self):
        inputs=self.fixture(); data=A.assemble(inputs,NOW)
        old=self.save('old-core.json',data['Deployment']); template=self.save('old-template.json',data['Materials'])
        previous=self.save('selection.json',dict(Deployment=old,MaterialsTemplate=template,Connections=data['Connections'],ExecutionProfile={'unchanged':True}))
        hold=self.save('hold.json',dict(Version='longhorn-ext4-freeze.v3',Sources=[],Clients=[]))
        core=copy.deepcopy(data['Deployment']); core['runtime_sources']['longhorn_hold']={'Materials':[hold]}
        core_pin=self.save('new-core.json',core)
        material=copy.deepcopy(data['Materials']); material['DeploymentConfigSHA256']=core_pin['SHA256']
        material_pin=self.save('new-template.json',material)
        selected=copy.deepcopy(A.obj(previous)); selected.update(Deployment=core_pin,MaterialsTemplate=material_pin)
        selected_pin=self.save('next-selection.json',selected)
        receipt=self.save('receipt.json',dict(Version='original-instance-mount-materials-receipt.v1',SelectionSHA256=previous['SHA256'],
            Deployment=core_pin,MaterialsTemplate=material_pin,SourceSelection=selected_pin,LonghornHoldMaterials=hold))
        host=self.save('host.json',dict(Version='original-observer-host-deployment.v1',LonghornVolumes={'File':'','SHA256':''}))
        definition=self.save('pki-definition.json',{'fixture':'definition'})
        return previous,receipt,host,definition,inputs['ObserverReceipt']

    def test_longhorn_successor_is_one_core_template_source_and_node_generation(self):
        args=self.successor(); handoff=A.longhorn_successor(*args)
        self.assertEqual(handoff['HostDefinition']['LonghornVolumes'],handoff['LonghornHoldMaterials'])
        self.assertEqual(A.obj(handoff['SourceSelection'])['Deployment'],handoff['Deployment'])
        registry=self.save('v2-record.json',dict(SchemaVersion='system-backup-original-bootstrap-source-registries.v2',Source=dict(Deployment=handoff['Deployment'],Materials=handoff['MaterialsTemplate'])))
        consumer=self.save('consumer.json',{'fixture':'consumer locator'})
        consumer_pin=self.save('consumer.sha256',consumer['SHA256'].encode())
        host=copy.deepcopy(handoff['HostDefinition']); host['LonghornSourceRegistry']={'Registry':dict(RecordFile=registry['File'],RecordSHA256=registry['SHA256'],SignatureFile='fixture-only'), 'CaptureConsumer':consumer,'CaptureConsumerPin':consumer_pin}
        R.check_host_source_core(host,handoff)
        stale=A.obj(registry); stale['Source']['Deployment']=A.obj(args[0])['Deployment']
        bad=self.save('old-v2-record.json',stale)
        host['LonghornSourceRegistry']['Registry'].update(RecordFile=bad['File'],RecordSHA256=bad['SHA256'])
        with self.assertRaisesRegex(ValueError,'old Core'): R.check_host_source_core(host,handoff)
        receipt=A.obj(args[1]); receipt['Deployment']=A.obj(args[0])['Deployment']
        changed=self.save('stale-receipt.json',receipt)
        with self.assertRaisesRegex(ValueError,'pins differ'):
            A.longhorn_successor(args[0],changed,*args[2:])

    def test_unknown_native_send_is_not_retried(self):
        # Exercise journal failure after a real subprocess launch boundary,
        # without starting a native owner or giving fixtures any authority.
        from unittest.mock import patch
        bundle=self.save('operation.json',{'Owner':{},'Tools':{'system-backup-source-registries':{}},'Steps':{'mount':{}}})
        calls=[]
        def interrupted(argv,**kwargs):
            calls.append(argv); raise subprocess.TimeoutExpired(argv,1)
        with patch.object(R,'stage_argv',return_value=['test-only-native']), patch.object(R,'check_journal_directory'):
            with self.assertRaises(subprocess.TimeoutExpired): R.run_stage(bundle,'mount',self.root,True,interrupted)
            with self.assertRaisesRegex(ValueError,'never resend'): R.run_stage(bundle,'mount',self.root,True,interrupted)
        self.assertEqual(len(calls),1)

    def test_observed_two_app_pods_use_shared_claim_and_staging_node(self):
        snapshot=Path(os.environ['P2_SNAPSHOT'])
        files=A.audit_snapshot(snapshot.read_bytes())
        values=files['namespace-'+A.NS+'.json']['items']
        app=next(x for x in values if x['kind']=='Deployment' and x['metadata']['name']=='clawmanager-app')
        pods=[x for x in values if x['kind']=='Pod' and x['metadata']['name'].startswith('clawmanager-app-') and not x['metadata'].get('deletionTimestamp')]
        controller=next(x for x in values if x['kind']=='Pod' and x['metadata']['name'].startswith(A.CONTROLLER+'-'))
        claim=next(x for x in values if x['kind']=='PersistentVolumeClaim' and x['metadata']['name']=='clawmanager-workspaces')
        self.assertEqual(len(pods),2)
        # Status has been deliberately reduced by the exporter. Readiness is a
        # test fixture only; live assembly must get the actual ready statuses.
        for pod in pods:
            pod['status']={'phase':'Running','containerStatuses':[{'ready':True}]}
        nodes={x['metadata']['name']:x['metadata']['uid'] for x in files['nodes.json']['items']}
        coordinates={'Namespace':A.NS,'NodeUIDs':nodes,'Volumes':[{'ClaimName':claim['metadata']['name'],'ClaimUID':claim['metadata']['uid']}]}
        class M:
            need=staticmethod(A.need); decode=staticmethod(A.decode)
        class Stages:
            op=types.SimpleNamespace(k=lambda *args:A.encode({'items':pods}))
            def get(self,kind,name): return controller if kind=='pod' else claim
        assembly=types.SimpleNamespace(original_app_environment=lambda *args:b'/workspaces')
        host={'Pod':controller['metadata']['name'],'PodUID':controller['metadata']['uid']}
        _,workspace,_=C.workspace(M,Stages(),assembly,app,host,coordinates)
        self.assertEqual(workspace['node'],controller['spec']['nodeName'])
        pods[1]['spec']['containers'][0]['volumeMounts']=[{'name':'workspaces','mountPath':'/wrong'}]
        with self.assertRaises(ValueError): C.workspace(M,Stages(),assembly,app,host,coordinates)

    def test_controller_patch_keeps_actual_waiter_and_does_not_enable_admission(self):
        files=A.audit_snapshot(Path(os.environ['P2_SNAPSHOT']).read_bytes())
        deployment=next(x for x in files['namespace-'+A.NS+'.json']['items'] if x['kind']=='Deployment' and x['metadata']['name']==A.CONTROLLER)
        tree=ast.parse((ROOT.parent/'system-backup-validation-bootstrap-preflight.py').read_text(encoding='utf-8'))
        launcher=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='LAUNCHER' for t in n.targets))
        deployment['metadata']['resourceVersion']='fixture-runtime-version'
        controller=next(c for c in deployment['spec']['template']['spec']['containers'] if c['name']=='controller')
        controller['command']=['/bin/sh','-ec',launcher]
        binary={'File':'/run/system-backup/bin/system-backup-v2-controller','SHA256':'a'*64}
        patch=A.waiting_controller_patch(deployment,binary)
        self.assertEqual([x['op'] for x in patch],['test','test','test','replace'])
        self.assertTrue(patch[-1]['path'].endswith('/command'))
        self.assertIn('while test ! -f "$f.ready"',patch[-1]['value'][2])
        self.assertIn('sha256sum /run/system-backup/bin/system-backup-v2-controller',patch[-1]['value'][2])
        controller['env'].append({'name':'SYSTEM_BACKUP_ENABLED','value':'true'})
        with self.assertRaises(ValueError): A.waiting_controller_patch(deployment,binary)

    def test_native_cli_flags_match_closed_actual_go_entry_points(self):
        # Validate command assembly against the actual native CLI declaration,
        # not a mock subprocess pretending to issue credentials or grants.
        paths={
            'system-backup-source-registries':'main.go',
            'system-backup-original-observer-pki':'main.go',
            'system-backup-observer-deployment-materials':'main.go',
            'system-backup-first-install-materials':'original_initial_source.go'}
        import re
        for stage,(binary,prefix,input_key) in R.STAGES.items():
            if binary=='system-backup-first-install-materials':
                source='\n'.join(p.read_text() for p in (ROOT.parents[1]/'backend/cmd'/binary).glob('*.go'))
            else: source=(ROOT.parents[1]/'backend/cmd'/binary/paths[binary]).read_text()
            expected=['plan-file','plan-sha256','issuer-public-file','issuer-public-sha256','enrollment-pin-file','enrollment-pin-sha256',
                      'kubeconfig-file','kubeconfig-sha256','dsn-file','database-ca-file','local-admin-password-file']
            if input_key: expected += ['mount-layouts-file','mount-layouts-sha256'] if stage=='mount' else ['definition-file','definition-sha256']
            if stage in ['mount','facts']: expected += ['source-selection-file','source-selection-sha256']
            if stage!='facts': expected += ['output-directory']
            for flag in expected:
                self.assertIn('"'+flag+'"',source,(stage,flag))

    def test_vault_tag_cannot_become_verified_image_or_new_owner(self):
        from unittest.mock import patch
        installer=self.save('system-backup-d-transit-install.py',b'fixture reviewed installer')
        plan=self.save('plan.json',dict(Target=dict(Namespace=A.NS,NamespaceUID='selected-ns')))
        kube=self.save('kubeconfig',b'fixture credential never print')
        image=self.save('vault-image.json',dict(schema_version='d-transit-image-input.v1',image='10.130.14.23:5000/clawmanager-backup-vault@sha256:'+'a'*64,
            entrypoint='/bin/vault',version='2.2.1',image_id_digests=['sha256:'+'a'*64]))
        inputs=dict(Version='p2-existing-vault-owner-inputs.v1',Plan=plan,Installer=installer,Kubeconfig=kube,ImageInput=image,NamespaceUID='selected-ns',Nodes=V.NODES,
                    Operation='install',StateDirectory=str(self.root/'new-vault-owner'),Node='k8s-master',StorageClass='longhorn')
        with patch.object(V,'PLAN_SHA',plan['SHA256']),patch.object(V,'INSTALLER_SHA',installer['SHA256']):
            _,argv=V.prepare(inputs)
            self.assertIn('--image-input-sha256',argv)
            bad=A.obj(image); bad['image']='10.130.14.23:5000/clawmanager-backup-vault:2.2.1-2194d86d'
            inputs['ImageInput']=self.save('vault-tag.json',bad)
            with self.assertRaisesRegex(ValueError,'tag is insufficient'): V.prepare(inputs)


if __name__=='__main__': unittest.main()
