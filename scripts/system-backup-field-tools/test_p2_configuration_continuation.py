"""Recorded DATA fixtures only; never authenticates or simulates a native owner."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent
def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),ROOT/name)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
A=load('assemble-p2-installation-candidate.py')
G=load('prepare-p2-configuration-data.py')
P=load('prepare-p2-metadata-read-access.py')
T=load('test_p2_installation_candidate.py')


class ConfigurationContinuation(unittest.TestCase):
    setUp=T.CandidateIntegration.setUp
    save=T.CandidateIntegration.save

    def ready(self):
        initial=T.CandidateIntegration.fixture(self)
        files=A.audit_snapshot(Path(os.environ['P2_SNAPSHOT']).read_bytes())
        items=copy.deepcopy(files['namespace-'+A.NS+'.json']['items']+files['namespace-'+A.TENANT+'.json']['items']+files['nodes.json']['items']+files['storage.json']['items'])
        # Hydration is confined to this D test fixture. These values are never
        # exported as field data or counted as real startup/issuer evidence.
        def fixture(v):
            if isinstance(v,list):return [fixture(x) for x in v]
            if not isinstance(v,dict):return v
            if v.get('redacted') is True:return 'test-fixture-only'
            out={k:fixture(x) for k,x in v.items() if k!='data_keys'}
            for k in ['command','args']:
                if k in out and not isinstance(out[k],list):out[k]=[]
            if out.get('kind') in ['Secret','ConfigMap']:out['data']={}
            return out
        items=fixture(items)
        app=next(x for x in items if x['kind']=='Deployment' and x['metadata']['name']=='clawmanager-app')
        for p in items:
            if p['kind']=='Pod' and p['metadata']['name'].startswith('clawmanager-app-'):
                p['status']={'phase':'Running','containerStatuses':[{'ready':True}]}
        worker=next(x for x in items if x['kind']=='ServiceAccount' and 'worker' in x['metadata']['name'])
        for suffix in ['resources','secrets']:
            items.append({'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':'sbk-d4f51b83b57e-'+suffix,'namespace':A.NS,'uid':'fixture-'+suffix},'automountServiceAccountToken':False})
        raw_graph=self.save('raw-kubernetes.fixture.json',{'items':items})
        installation='installation_fixture_only'
        plan=self.save('real-shaped-plan.fixture.json',{'Target':{'Namespace':A.NS,'NamespaceUID':'fixture-ns','InstallationID':installation,'ServerUUID':'actual-uuid','Database':'testdb'}})
        sqlop=A.obj(initial['SQLOperation']);sqlop['Census']={'fixture':True}
        initial['SQLOperation']=self.save('sql-operation-with-census.fixture.json',sqlop)
        sql=self.save('sql-materials.fixture.json',{'server_uuid':'actual-uuid','database':'testdb',
            'files':{'mysql-source.dsn':initial['SourceDSN'],'mysql-control_sql.dsn':initial['ControlDSN']},
            'source_tls':{'ca_file':initial['DatabaseCA']['File'],'ca_sha256':initial['DatabaseCA']['SHA256'],'server_name':'mysql.fixture'}})
        ca=A.obj(initial['ObserverReceipt'])['CA']
        cert=A.obj(initial['ObserverReceipt'])['ClientCertificate'];key=A.obj(initial['ObserverReceipt'])['ClientKey']
        manifest=self.save('relay-manifest.fixture.json',{'fixture':True})
        pki=self.save('relay-receipt.fixture.json',dict(DeploymentUID=A.CONTROLLER_UID,Endpoint='https://controller.fixture:9443/relay',Manifest=manifest,
            CA=ca,IssuerKey=key,ServerCertificate=cert,ServerKey=key))
        observer=A.obj(initial['ObserverReceipt']);observer.update(ClientURI='spiffe://fixture.invalid/client',Endpoints=[])
        for kind in ['shared','whole','stopped-pro']:
            observer['Endpoints'].append({'Kind':kind,'Node':'node1','Endpoint':{'URL':'https://node.fixture:9444/proof','ServerURI':'spiffe://fixture.invalid/'+kind}})
        observer_pin=self.save('fresh-observer.fixture.json',observer)
        redis=A.obj(initial['Redis']);keeper=A.obj(redis['KeeperSelection']);policy={'Policy':{'Source':{'ID':'fixture-redis'},'DB':0,'Prefixes':['fixture:']},'ServerID':'fixture-redis-server','ExcludePrefixes':[]}
        keeper['Native']['Policy']=policy;keeper.update(ServerName='redis.fixture',Port=6380,CA=ca)
        redis.update(KeeperSelection=self.save('actual-keeper.fixture.json',keeper),Policy=self.save('actual-policy.fixture.json',policy))
        redis_pin=self.save('redis-fragment.fixture.json',redis)
        dep_names=['clawmanager-app','openclaw-runtime','hermes-runtime']
        deps=[x for x in items if x['kind']=='Deployment' and x['metadata']['name'] in dep_names]
        writer=self.save('writer.fixture.json',{'SharedRuntimeProtocol':'shared-container-freeze.v1','Participants':[],
            'ApplicationScope':'installation','AgentCredential':initial['ControlDSN'],'AgentCA':ca,'RedisReadKeepers':[keeper],
            'Deployments':[{'Name':x['metadata']['name'],'UID':x['metadata']['uid'],'Role':'writer' if x['metadata']['name']=='clawmanager-app' else 'agent'} for x in deps],
            'Policy':{'AcquisitionTimeout':60000000000,'MaxHold':600000000000}})
        app_env=app['spec']['template']['spec']['containers'][0]['env']
        app_env[:]=[e for e in app_env if e['name']!='RUNTIME_AGENT_CA_SHA256']
        app_env.append({'name':'RUNTIME_AGENT_CA_SHA256','value':ca['SHA256']})
        volumes=[]
        for x in items:
            if x['kind']=='PersistentVolumeClaim':volumes.append({'ClaimName':x['metadata']['name'],'ClaimUID':x['metadata']['uid'],'PVName':x['spec'].get('volumeName','fixture-pv'),'PVUID':'fixture-pv-uid','PVSpecSHA256':'a'*64})
        tenant=next(x for x in items if x['kind']=='Pod' and x['metadata'].get('namespace')==A.TENANT)
        sources=[{'ID':1,'UserID':1,'Generation':2,'Type':'openclaw','Mode':'lite','Backend':'gateway','Variant':'','OS':'linux','Status':'running','Workspace':'/workspaces/openclaw/user-1/instance-1'},
                 {'ID':2,'UserID':1,'Generation':0,'Type':'openclaw','Mode':'pro','Backend':'desktop','Variant':'','OS':'linux','Status':'running','Workspace':'/config'}]
        nodes={x['metadata']['name']:x['metadata']['uid'] for x in items if x['kind']=='Node'}
        coords=self.save('coordinates.fixture.json',{'Namespace':A.NS,'NamespaceUID':'fixture-ns','InstallationID':installation,'NodeUIDs':nodes,'Volumes':volumes,'Instances':sources,
            'SharedNodes':[{'Name':'node1','UID':nodes['node1'],'Paths':['/workspaces/openclaw/user-1/instance-1']}],
            'Storage':[{'InstanceID':x['ID'],'RuntimeImageReference':'fixture-runtime-'+str(x['ID'])} for x in sources],
            'Layouts':[{'Source':sources[1],'CurrentPod':tenant['metadata']['name'],'CurrentPodUID':tenant['metadata']['uid'],'CurrentNamespace':A.TENANT}]})
        profile=self.save('profile.fixture.json',{'installation_id':installation})
        effective=self.save('effective-config.fixture.json',{'Version':'original-application-config-coordinates.v1','WorkspaceRoot':'/workspaces','ObjectBucket':'fixture-bucket','ObjectPrefix':'fixture-prefix','RuntimeQualified':False,'BackupReady':False})
        config=self.save('image-config.fixture.json',{'os':'linux','architecture':'amd64','config':{'Labels':{'org.opencontainers.image.revision':'1'*40}}})
        image_manifest=self.save('image-manifest.fixture.json',{'config':{'digest':'sha256:'+config['SHA256'],'size':len(A.read(config))}})
        image=self.save('immutable-image.fixture.json',{'Reference':'10.130.14.23:5000/fixture@sha256:'+image_manifest['SHA256'],'Manifest':image_manifest,'Config':config})
        app['spec']['template']['spec']['containers'][0]['image']=A.obj(image)['Reference']
        # Re-pin after the fixture-only image update.
        raw_graph=self.save('updated-raw-kubernetes.fixture.json',{'items':items})
        runtimes=[]
        for kind in ['openclaw','hermes']:
            runtimes.append({'Manifest':self.save(kind+'-manifest.json',{'fixture':kind}),'Config':config})
        startup=self.save('startup.fixture.json',{'Version':'original-runtime-startup-image-inputs.v1','Images':runtimes})
        api=A.obj(initial['SourceAPI']);api['service_account']='fixture-sources'
        helper=self.save('system-backup-initial-complete-inputs.py',(ROOT.parent/'system-backup-initial-complete-inputs.py').read_bytes().replace(b'\r\n',b'\n'))
        return {'Version':'p2-ready-initial-producers.v1','CompleteInputsHelper':helper,
            'Plan':plan,'SQLMaterials':sql,'SQLOperation':initial['SQLOperation'],'Coordinates':coords,'WriterSelection':writer,'ExecutionProfile':profile,
            'RelayPKI':pki,'ObserverReceipt':observer_pin,'WorkerDefinition':self.save('worker-definition.fixture.json',{'Name':worker['metadata']['name'],'ExistingUID':worker['metadata']['uid']}),
            'KubernetesObjects':[raw_graph],'SourceIssuerPublic':initial['SourceIssuerPublic'],'Enrollment':self.save('enrollment.fixture.json',{'fixture':True}),
            'AppImage':image,'WorkerImage':image,'EffectiveAppConfig':effective,'RuntimeIssuers':initial['RuntimeIssuers'],'RuntimeStartupInputs':startup,
            'SourceAPI':self.save('source-api.fixture.json',api),'Redis':redis_pin,'MinIO':initial['MinIO'],'NotBefore':'2026-11-11T09:30:00Z','Until':'2026-11-11T11:00:00Z'}

    def test_named_producers_generate_configuration_and_initial_definition_without_native_calls(self):
        ready=self.ready();out=self.root/'generated';out.mkdir()
        result=G.compile_data(ready,out,self.root)
        self.assertFalse(result['NativeAuthorCalled']);self.assertFalse(result['ProviderOrRedisApplied'])
        definition=A.assemble(A.obj(result['AssemblyInputs']),T.NOW)
        self.assertEqual([c['Purpose'] for c in definition['Connections']],A.PURPOSES)
        self.assertEqual(definition['Deployment']['runtime_sources']['lease_participants'],[])
        self.assertEqual(definition['Materials']['Redis']['RedisScope']['ID'],'fixture-redis')
        self.assertEqual(definition['Controller']['DeploymentUID'],A.CONTROLLER_UID)
        self.assertEqual(definition['Deployment']['trust_domain'],'fixture.invalid')
        # The recorded running Pro uses :latest in its unchanged original
        # spec, but the policy selects its own exact CRI-loaded digest.
        pro=[p for p in definition['Materials']['Discovery']['RuntimePolicies'] if p['Runtime']['mode']=='pro']
        self.assertEqual(pro[0]['Image'],'ghcr.io/yuan-lab-llm/agentsruntime/openclaw@sha256:3fa27eac797ec0563ab44b835ed2c060ab06c9b3b2e136203091486d225b35e3')
        graph=A.obj(ready['KubernetesObjects'][0])
        tenant=next(x for x in graph['items'] if x['kind']=='Pod' and x['metadata'].get('namespace')==A.TENANT)
        tenant['status']['containerStatuses'][0]['imageID']='foreign/image@sha256:'+'a'*64
        bad=dict(ready,KubernetesObjects=[self.save('wrong-pro-image.fixture.json',graph)])
        another=self.root/'bad-data';another.mkdir()
        with self.assertRaisesRegex(ValueError,'repository_mismatch'):G.compile_data(bad,another,self.root)

    def test_missing_profile_is_configured_from_original_tls_and_recorded_topology_not_dr_evidence(self):
        ready=self.ready();ready.pop('ExecutionProfile')
        graph=A.obj(ready['KubernetesObjects'][0]);items=graph['items']
        items.append({'kind':'Namespace','metadata':{'name':'kube-system','uid':'fixture-cluster'}})
        ready['KubernetesObjects']=[self.save('profile-graph.fixture.json',graph)]
        objects=G.RecordedObjects(ready['KubernetesObjects'])
        pod=next(x for x in items if x['kind']=='Pod' and x['metadata']['namespace']==A.NS and x['metadata']['name'].startswith('minio-'))
        parent=next(r for r in pod['metadata']['ownerReferences'] if r.get('controller'))
        resources={'deployment':objects.get('deployment','minio'),'replicaset':objects.get('replicaset',parent['name']),
            'pod':pod,'service':objects.get('service','minio'),'service_account':objects.get('serviceaccount',pod['spec'].get('serviceAccountName','default')),
            'node':objects.get('node',pod['spec']['nodeName'])}
        state=pod['status']['containerStatuses'][0];ca=A.obj(ready['ObserverReceipt'])['CA']
        ready['MinIOTLSReceipt']=self.save('minio-tls.fixture.json',{'state':'actual_tls_verified','permission_gate_or_adoption':False,
            'objects':{k:{'name':x['metadata']['name'],'uid':x['metadata']['uid']} for k,x in resources.items()},
            'container':state['name'],'container_id':state['containerID'],'image_id':state['imageID'],'ca_file':ca['File'],'ca_sha256':ca['SHA256'],
            'endpoint':'https://minio.'+A.NS+'.svc:9000','server_name':'minio.'+A.NS+'.svc','spki_sha256':'a'*64,'leaf_sha256':'b'*64})
        helper=ROOT.parent/'system-backup-initial-provider-topology.py'
        ready['ProviderTopologyHelper']=self.save(helper.name,helper.read_bytes().replace(b'\r\n',b'\n'))
        plan=A.obj(ready['Plan']);plan.update(KubernetesAPI='https://fixture-api:6443',KubernetesCASHA256='a'*64)
        out=self.root/'profile-output';out.mkdir()
        profile=G.configured_profile(ready,objects,plan,out)
        self.assertEqual(profile['target_class'],'same-cluster-copy')
        self.assertIn('attestation_missing',profile['target_risks'])
        self.assertEqual(profile['target_failure_domain_id'],'cluster:fixture-cluster')

    def test_raw_recorded_input_refuses_redacted_export(self):
        pin=self.save('redacted.fixture.json',{'kind':'Secret','metadata':{'name':'x'},'data_keys':['password']})
        with self.assertRaisesRegex(ValueError,'redacted export'):G.RecordedObjects([pin])

    def test_oci_metadata_has_a_real_read_entry_but_does_not_claim_release_qualification(self):
        import io
        config=A.encode({'os':'linux','architecture':'amd64','config':{'Labels':{'org.opencontainers.image.revision':'1'*40}}})
        manifest=A.encode({'schemaVersion':2,'config':{'digest':'sha256:'+A.sha(config),'size':len(config)}})
        class Response(io.BytesIO): status=200
        class Client:
            calls=[]
            def open(self,request,timeout):
                self.calls.append(request.full_url)
                return Response(manifest if '/manifests/' in request.full_url else config)
        directory=self.root/'oci-data';directory.mkdir();client=Client()
        result=G.read_image_data('10.130.14.23:5000/fixture@sha256:'+A.sha(manifest),directory,client)
        self.assertEqual(len(client.calls),2);self.assertFalse(result['NativeReleaseQualified'])
        self.assertEqual(A.read(A.obj(result['ImageData'])['Manifest']),manifest)
        with self.assertRaises(ValueError):G.read_image_data('10.130.14.23:5000/fixture:latest',directory,client)

    def test_unlabelled_image_metadata_can_be_retained_but_cannot_supply_build_commit(self):
        import io
        config=A.encode({'os':'linux','architecture':'amd64','config':{}})
        manifest=A.encode({'schemaVersion':2,'config':{'digest':'sha256:'+A.sha(config),'size':len(config)}})
        class Response(io.BytesIO): status=200
        class Client:
            def open(self,request,timeout):return Response(manifest if '/manifests/' in request.full_url else config)
        directory=self.root/'unlabelled';directory.mkdir()
        result=G.read_image_data('10.130.14.23:5000/fixture@sha256:'+A.sha(manifest),directory,Client())
        self.assertFalse(result['NativeReleaseQualified'])
        with self.assertRaisesRegex(ValueError,'source-labelled'):G.immutable_image(result['ImageData'])

    def test_completed_rotation_selects_new_ca_without_rewriting_original_writer(self):
        ready=self.ready();writer=A.obj(ready['WriterSelection']);original=A.read(ready['WriterSelection'])
        new=self.save('renewed-agent-ca.fixture.pem',b'new fixture CA\n')
        graph=A.obj(ready['KubernetesObjects'][0]);items=graph['items']
        app=next(x for x in items if x['kind']=='Deployment' and x['metadata']['name']=='clawmanager-app')
        spec=app['spec']['template']['spec'];c=spec['containers'][0]
        for e in c['env']:
            if e['name']=='RUNTIME_AGENT_CA_SHA256':e['value']=new['SHA256']
        c['volumeMounts']=[m for m in c.get('volumeMounts',[]) if m['mountPath']!='/run/clawmanager-agent-ca']
        c['volumeMounts'].append({'name':'renewed-ca','mountPath':'/run/clawmanager-agent-ca','readOnly':True})
        spec.setdefault('volumes',[]).append({'name':'renewed-ca','configMap':{'name':'fixture-renewed-ca'}})
        items.append({'kind':'ConfigMap','metadata':{'namespace':A.NS,'name':'fixture-renewed-ca'},'immutable':True,'data':{'ca.pem':A.read(new).decode()}})
        targets=[]
        for name in ['hermes-runtime','openclaw-runtime']:
            d=next(x for x in items if x['kind']=='Deployment' and x['metadata']['name']==name)
            secret='renewed-'+name
            d['spec']['template']['spec'].setdefault('volumes',[]).append({'name':'renewed-tls','secret':{'secretName':secret}})
            targets.append({'Deployment':name,'DeploymentUID':d['metadata']['uid'],'SecretName':secret})
        ready['KubernetesObjects']=[self.save('renewed-graph.fixture.json',graph)]
        objects=G.RecordedObjects(ready['KubernetesObjects']);plan=A.obj(ready['Plan'])
        with self.assertRaisesRegex(ValueError,'App CA differs'):G.runtime_agent_ca(ready,objects,writer,plan)
        receipt={'Version':'original-shared-agent-tls-materials.v1','Namespace':A.NS,'NamespaceUID':plan['Target']['NamespaceUID'],
                 'NotBefore':'2026-11-11T09:00:00Z','NotAfter':'2026-11-11T12:00:00Z','CA':new,'Targets':targets}
        ready['RuntimeAgentTLS']=self.save('renewed-runtime-tls.fixture.json',receipt)
        completed={'Version':'p2-runtime-certificate-rotation.v1','CA':new,'NotAfter':receipt['NotAfter'],'ImagesPreserved':True,'BackupReady':False}
        ready['RuntimeAgentRotation']=self.save('completed-rotation.fixture.json',completed)
        self.assertEqual(G.runtime_agent_ca(ready,objects,writer,plan),new)
        out=self.root/'renewed-configuration';out.mkdir()
        result=G.compile_data(ready,out,self.root)
        data=A.obj(result['ConfigurationData'])
        self.assertEqual(data['RuntimeAgent']['CA']['SHA256'],new['SHA256'])
        self.assertEqual(A.read(ready['WriterSelection']),original)
        completed['CA']=writer['AgentCA']
        bad=dict(ready,RuntimeAgentRotation=self.save('mismatched-completion.fixture.json',completed))
        with self.assertRaisesRegex(ValueError,'same completed'):G.runtime_agent_ca(bad,objects,writer,plan)
        bad=dict(ready,Until='2026-11-11T13:00:00Z')
        with self.assertRaisesRegex(ValueError,'execution window'):G.runtime_agent_ca(bad,objects,writer,plan)
        badgraph=copy.deepcopy(graph)
        next(x for x in badgraph['items'] if x['kind']=='ConfigMap' and x['metadata']['name']=='fixture-renewed-ca')['data']['ca.pem']='wrong CA'
        with self.assertRaisesRegex(ValueError,'App CA bytes'):
            G.runtime_agent_ca(ready,G.RecordedObjects([self.save('wrong-ca-graph.fixture.json',badgraph)]),writer,plan)

    def test_longhorn_read_access_is_exact_additive_and_separate_from_actor_permissions(self):
        plan={'Target':{'Namespace':A.NS,'NamespaceUID':'original-system'}}
        api={'connection':{'Account':'source-uid'},'service_account_uid':'source-uid','service_account':'original-sources'}
        provider={'kind':'Namespace','metadata':{'name':'longhorn-system','uid':'original-provider'}}
        role,binding,actors,guards=P.render(plan,api,provider)
        self.assertEqual(P.render(plan,api,{'items':[provider]})[3],guards)
        self.assertEqual(role['rules'],[{'apiGroups':[''],'resources':['pods','services'],'verbs':['get','list']}])
        self.assertEqual(binding['subjects'][0]['namespace'],A.NS)
        self.assertTrue(all(x['automountServiceAccountToken'] is False for x in actors))
        self.assertFalse(guards['Applied']);self.assertTrue(guards['ExistingBindingsPreserved'])


if __name__=='__main__':unittest.main()
