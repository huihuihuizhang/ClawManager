#!/usr/bin/env python3
"""Compile initial ConfigurationData from named original producer inputs.

Only local DATA projection: no subprocess, network, issuer, provider lifecycle,
Redis prepare/apply, ServiceAccount creation or source-facts claim. Recorded
Kubernetes objects are explicitly historical input, not simulated live reads.
The unchanged native initial-source author must authenticate the result live.
"""
import argparse
import base64
import copy
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from dataclasses import asdict
from types import SimpleNamespace
from urllib.parse import urlsplit
import urllib.request


def load(name):
    p=Path(__file__).with_name(name)
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),p)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m


A=load('assemble-p2-installation-candidate.py')
ORIGINAL_HELPERS={
    'system-backup-initial-complete-inputs.py':'c3c26a71f18dddff3315045b0c8e1849302e641bee49374759010b37d79f8d06',
    'system-backup-initial-provider-topology.py':'62767abc3844e123383cde955b36a1ef0d4c6020f12f5a01bfe417bd75bb2cd7',
}


def module_from_pin(pin):
    A.need(ORIGINAL_HELPERS.get(Path(pin['File']).name)==pin['SHA256'],'only reviewed original DATA helper code may be loaded')
    A.read(pin)
    name='p2_recorded_'+Path(pin['File']).stem.replace('-','_')
    spec=importlib.util.spec_from_file_location(name,pin['File'])
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


def local_pin(path):
    path=Path(path)
    value={'File':str(path),'SHA256':A.sha(path.read_bytes())};A.read(value)
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError('registry redirect refused')


def read_image_data(reference,directory,opener=None):
    """Explicit future read-only OCI metadata step, not release qualification."""
    match=re.fullmatch(r'10\.130\.14\.23:5000/([a-z0-9][a-z0-9._/-]{0,200})@sha256:([a-f0-9]{64})',reference or '')
    A.need(match and all(p not in ['','.','..'] for p in match[1].split('/')),'explicit immutable image selection required')
    client=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def fetch(kind,digest):
        A.need(re.fullmatch('[a-f0-9]{64}',digest),'actual OCI digest required')
        url='http://10.130.14.23:5000/v2/'+match[1]+'/'+kind+'/sha256:'+digest
        request=urllib.request.Request(url,headers={'Accept':'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'})
        with client.open(request,timeout=30) as response:
            A.need(response.status==200,'registry metadata read unconfirmed')
            raw=response.read((4<<20)+1)
        A.need(0<len(raw)<=4<<20 and A.sha(raw)==digest,'actual registry bytes changed or exceeded limit')
        return raw
    manifest_raw=fetch('manifests',match[2]);manifest=A.decode(manifest_raw)
    A.need(manifest.get('schemaVersion')==2 and 'manifests' not in manifest and manifest['config']['digest'].startswith('sha256:'),'single actual image manifest required')
    config_raw=fetch('blobs',manifest['config']['digest'].removeprefix('sha256:'))
    value={'Reference':reference,'Manifest':A.retain(directory/'image-manifest.json',manifest_raw),
           'Config':A.retain(directory/'image-config.json',config_raw),'NativeQualified':False}
    pin=A.retain(directory/'image-data.json',value)
    immutable_image(pin,require_revision=False)
    return {'ImageData':pin,'ActualMetadataBytesRead':True,'NativeReleaseQualified':False,'BackupReady':False}


def writer_selection_pin(receipt):
    # prepare-selection returns Selection; native delivery successors return
    # WriterSelection. Consume their real pin without inventing a new receipt.
    if receipt.get('Version')=='original-writer-selection-materials.v1':
        A.need(receipt.get('State')=='actual_original_complete_base_selection_materialized_no_hold' and
               receipt.get('SourceCount')==8,'complete original base selection receipt required')
        return receipt['Selection']
    return receipt['WriterSelection']


def prepare_index(args):
    """Locate retained field producers; never asks the operator to handwrite Core."""
    work=Path('/root/sbk-validation-tls-inspect.7LVU7vpE')
    sql=work/'fresh-sql-prepare.faa4osWr/sql-operation'
    native=work/'fresh-sql-prepare.faa4osWr/fresh-backup-enrollment-r2/native'
    def supplied(name):
        file=getattr(args,name+'_file');digest=getattr(args,name+'_sha256')
        A.need(file and digest,'actual producer file/pin required: '+name)
        pin={'File':file,'SHA256':digest};A.read(pin);return pin
    raw_index=A.obj(supplied('raw_index'))
    A.need(raw_index['version'] in ['p2-redacted-offline-inventory.v1','p2-current-kubernetes-inputs.v1'] and raw_index['errors']==[], 'complete original raw-input index required')
    by_label={p['label']:{'File':p['File'],'SHA256':p['SHA256']} for p in raw_index['remote_private_inputs']}
    values={'Version':'p2-ready-initial-producers.v1','Plan':local_pin(native/'original-enrollment-plan.json'),
        'Enrollment':local_pin(native/'original-enrollment-pin.json'),'SourceIssuerPublic':local_pin(native/'issuer.public'),
        'SQLMaterials':local_pin(sql/'sql-accounts-materials.public.json'),'SQLOperation':local_pin(sql/'operation.json'),
        'Coordinates':local_pin(Path('/root/sbk/p2-materials-1dd1ae71.lVSEBfl2/coordinates/initial-source-coordinates.json')),
        'WriterSelection':local_pin(Path('/root/sbk/p2-redis-connection.b5dQ12Lt/native/redis-native-writer-selection.json')),
        'WorkerDefinition':local_pin(work/'fresh-backup-bootstrap/worker-sa.definition.json'),
        'RuntimeStartupInputs':local_pin(Path('/root/sbk/p2-materials-1dd1ae71.lVSEBfl2/runtime-startup-images/runtime-startup-images.json')),
        'EffectiveAppConfig':local_pin(Path('/root/sbk/p2-minio-prepare.9vnemhVi/connection-continuation/effective-app-config.json')),
        'MinIOTLSReceipt':local_pin(Path('/root/sbk/p2-minio-prepare.9vnemhVi/connection-continuation/minio.latest.receipt.json')),
        'KubernetesObjects':[by_label[k] for k in ['namespaces','nodes','storage','namespace-'+A.NS,'namespace-'+A.TENANT]],
        'CompleteInputsHelper':local_pin(Path(__file__).with_name('system-backup-initial-complete-inputs.py')),
        'ProviderTopologyHelper':local_pin(Path(__file__).with_name('system-backup-initial-provider-topology.py')),
        'RelayPKI':supplied('relay_receipt'),'ObserverReceipt':supplied('observer_receipt'),
        'AppImage':supplied('app_image_data'),'WorkerImage':supplied('worker_image_data')}
    for key in ['MinIO','Redis','SourceAPI','RuntimeIssuers']:values[key]=A.KNOWN[key]
    # Refreshes are explicit producer outputs, never newest-directory selection.
    for name,key,field in [('source_api','SourceAPI',None),('runtime_issuers','RuntimeIssuers',None),('coordinates_receipt','Coordinates','Coordinates'),('writer_receipt','WriterSelection','WriterSelection')]:
        if getattr(args,name+'_file'):
            pin=supplied(name)
            values[key]=writer_selection_pin(A.obj(pin)) if key=='WriterSelection' else A.obj(pin)[field] if field else pin
    for key in ['MinIO','Redis','SourceAPI','RuntimeIssuers','Coordinates','WriterSelection']:A.read(values[key])
    if args.runtime_agent_tls_file or args.runtime_agent_rotation_file:
        values['RuntimeAgentTLS']=supplied('runtime_agent_tls')
        values['RuntimeAgentRotation']=supplied('runtime_agent_rotation')
    now=datetime.datetime.now(datetime.timezone.utc)
    observer=A.obj(values['ObserverReceipt']);api=A.obj(values['SourceAPI'])
    end=min(now+datetime.timedelta(hours=1),datetime.datetime.fromisoformat(observer['NotAfter'].replace('Z','+00:00')),
            datetime.datetime.fromtimestamp(api['token_expires_unix'],datetime.timezone.utc))
    A.need(now<end,'genuine observer/API renewal required before assembling a new installation window')
    values.update(NotBefore=(now-datetime.timedelta(seconds=5)).isoformat().replace('+00:00','Z'),Until=end.isoformat().replace('+00:00','Z'))
    retained=args.output_directory/'ready-producers.json'
    if retained.exists():
        old=A.decode(retained.read_bytes())
        A.need({k:v for k,v in old.items() if k not in ['NotBefore','Until']}==
               {k:v for k,v in values.items() if k not in ['NotBefore','Until']}, 'retained producer selection changed; preserve original operation')
        A.need(now<datetime.datetime.fromisoformat(old['Until'].replace('Z','+00:00')), 'retained DATA window expired; do not overwrite or resend a native operation')
        values=old
    return A.retain(args.output_directory/'ready-producers.json',values)


class RecordedObjects:
    """Finite raw producer objects; deliberately has no kubectl/HTTP transport."""
    def __init__(self,pins):
        self.items={}
        for pin in pins:
            value=A.obj(pin)
            def raw_only(v):
                if isinstance(v,list):
                    for x in v:raw_only(x)
                elif isinstance(v,dict):
                    A.need(v.get('redacted') is not True and 'data_keys' not in v and
                           not any(k in v and not isinstance(v[k],list) for k in ['command','args']),
                           'redacted export cannot be a raw runtime producer input')
                    for x in v.values():raw_only(x)
            raw_only(value)
            for item in value.get('items',[value]):
                key=(item['kind'],item['metadata'].get('namespace',''),item['metadata']['name'])
                A.need(key not in self.items or self.items[key]==item,'ambiguous recorded Kubernetes object')
                self.items[key]=item

    def get(self,kind,name,namespace=A.NS):
        kinds={'pod':'Pod','pvc':'PersistentVolumeClaim','pv':'PersistentVolume','namespace':'Namespace','deployment':'Deployment','replicaset':'ReplicaSet','serviceaccount':'ServiceAccount','service':'Service','secret':'Secret','configmap':'ConfigMap','node':'Node'}
        kind=kinds.get(kind,kind)
        if kind in ['Node','PersistentVolume','Namespace']: namespace=''
        key=(kind,namespace,name)
        A.need(key in self.items,'missing actual raw producer object: '+kind+'/'+namespace+'/'+name)
        return copy.deepcopy(self.items[key])

    def pods(self,namespace,labels):
        return [copy.deepcopy(v) for (k,ns,_),v in self.items.items() if k=='Pod' and ns==namespace and
                not v['metadata'].get('deletionTimestamp') and all(v['metadata'].get('labels',{}).get(k)==x for k,x in labels.items())]


def current_host(objects,plan,worker_definition):
    dep=objects.get('deployment',A.CONTROLLER)
    A.need(dep['metadata']['uid']==A.CONTROLLER_UID,'selected controller changed')
    pods=objects.pods(A.NS,dep['spec']['selector']['matchLabels'])
    A.need(len(pods)==1,'one recorded controller Pod required')
    pod=pods[0]
    def parent(item,kind):
        refs=[r for r in item['metadata'].get('ownerReferences',[]) if r.get('controller')]
        A.need(len(refs)==1 and refs[0]['kind']==kind,'recorded controller owner chain changed')
        return refs[0]
    ref=parent(pod,'ReplicaSet');rs=objects.get('replicaset',ref['name'])
    up=parent(rs,'Deployment')
    A.need(ref['uid']==rs['metadata']['uid'] and up['uid']==dep['metadata']['uid'] and up['name']==A.CONTROLLER,'recorded controller UID chain changed')
    sa=objects.get('serviceaccount',pod['spec']['serviceAccountName'])
    worker=objects.get('serviceaccount',worker_definition['Name'])
    A.need(not worker_definition.get('ExistingUID') or worker_definition['ExistingUID']==worker['metadata']['uid'],'original worker ServiceAccount changed')
    host=dict(Deployment=A.CONTROLLER,DeploymentUID=A.CONTROLLER_UID,Pod=pod['metadata']['name'],PodUID=pod['metadata']['uid'],
              ReplicaSet=rs['metadata']['name'],ReplicaSetUID=rs['metadata']['uid'],ServiceAccount=sa['metadata']['name'],ServiceAccountUID=sa['metadata']['uid'])
    staging=objects.get('pvc',A.CONTROLLER.replace('-controller','')+'-staging')
    return host,worker,staging


def immutable_image(pin,require_revision=True):
    """Actual OCI bytes supply config digest and source label, never a tag."""
    selected=A.obj(pin)
    reference=selected['Reference'];A.need(re.fullmatch(r'10\.130\.14\.23:5000/[^\s@]+@sha256:[a-f0-9]{64}',reference),'explicit immutable release image required')
    manifest_raw=A.read(selected['Manifest']); manifest=A.decode(manifest_raw)
    config_raw=A.read(selected['Config']); config=A.decode(config_raw)
    commit=(config.get('config',{}).get('Labels') or {}).get('org.opencontainers.image.revision','')
    A.need(reference.endswith('@sha256:'+A.sha(manifest_raw)) and manifest['config']['digest']=='sha256:'+A.sha(config_raw) and
           manifest['config']['size']==len(config_raw) and config['os']=='linux' and config['architecture']=='amd64',
           'actual linux/amd64 OCI bytes required')
    A.need(not require_revision or re.fullmatch('[a-f0-9]{40}',commit),
           'actual source-labelled linux/amd64 OCI bytes required')
    return dict(reference=reference,manifest_sha256=A.sha(manifest_raw),config_digest='sha256:'+A.sha(config_raw),commit=commit)


def runtime_agent_ca(inputs,objects,writer,plan):
    """Select retained CA DATA only after matching the completed rotation graph.

    This does not verify a live TLS session or authenticate an issuance. The
    original native author still reads the current runtime and its authority.
    """
    app=objects.get('deployment','clawmanager-app')
    spec=app['spec']['template']['spec'];containers=spec['containers']
    A.need(len(containers)==1,'one original App container required')
    env=[e for e in containers[0].get('env',[]) if e['name']=='RUNTIME_AGENT_CA_SHA256']
    A.need(len(env)==1 and 'value' in env[0],'recorded App CA pin required')
    selected=writer['AgentCA'];A.read(selected)
    if inputs.get('RuntimeAgentTLS') or inputs.get('RuntimeAgentRotation'):
        A.need(inputs.get('RuntimeAgentTLS') and inputs.get('RuntimeAgentRotation'),
               'genuine TLS receipt and completed rotation DATA required together')
        receipt=A.obj(inputs['RuntimeAgentTLS']);rotation=A.obj(inputs['RuntimeAgentRotation'])
        A.need(receipt['Version']=='original-shared-agent-tls-materials.v1' and
               receipt['Namespace']==A.NS and receipt['NamespaceUID']==plan['Target']['NamespaceUID'] and
               rotation['Version']=='p2-runtime-certificate-rotation.v1' and
               rotation['CA']==receipt['CA'] and rotation['NotAfter']==receipt['NotAfter'] and
               rotation['ImagesPreserved'] is True,'same completed runtime CA rotation required')
        moment=lambda s:datetime.datetime.fromisoformat(s.replace('Z','+00:00'))
        A.need(moment(receipt['NotBefore'])<=moment(inputs['NotBefore'])<moment(inputs['Until'])<=moment(receipt['NotAfter']),
               'runtime certificate must cover the selected execution window')
        selected=receipt['CA'];raw=A.read(selected)
        mounts=[m for m in containers[0].get('volumeMounts',[]) if m['mountPath']=='/run/clawmanager-agent-ca' and m.get('readOnly') is True]
        A.need(len(mounts)==1,'recorded App CA mount changed')
        volumes=[v for v in spec.get('volumes',[]) if v['name']==mounts[0]['name']]
        A.need(len(volumes)==1 and 'configMap' in volumes[0],'recorded App CA ConfigMap required')
        cm=objects.get('configmap',volumes[0]['configMap']['name'])
        A.need(cm.get('immutable') is True and cm.get('data',{}).get('ca.pem','').encode()==raw,
               'recorded App CA bytes do not match the completed rotation')
        targets=receipt['Targets']
        A.need(len(targets)==2 and {t['Deployment'] for t in targets}=={'hermes-runtime','openclaw-runtime'},
               'both original runtime TLS targets required')
        for target in targets:
            d=objects.get('deployment',target['Deployment']);pod=d['spec']['template']['spec']
            A.need(d['metadata']['uid']==target['DeploymentUID'] and
                   any(v.get('secret',{}).get('secretName')==target['SecretName'] for v in pod.get('volumes',[])),
                   'recorded runtime has not selected the renewed TLS Secret')
    A.need(env[0]['value']==selected['SHA256'],
           'App CA differs from retained writer; supply completed runtime rotation pins')
    return selected


def configured_profile(inputs,objects,plan,directory):
    """Reuse the existing typed topology model for functional configuration DATA.

    A single pinned historical graph is projected once. We do not claim that
    two live reads, current readiness, a restore or a new TLS probe ran here.
    """
    if inputs.get('ExecutionProfile'):return A.obj(inputs['ExecutionProfile'])
    topology=module_from_pin(inputs['ProviderTopologyHelper'])
    receipt_pin=inputs['MinIOTLSReceipt'];actual=A.obj(receipt_pin);target=plan['Target']
    A.need(actual['state']=='actual_tls_verified' and actual['permission_gate_or_adoption'] is False,
           'actual original MinIO TLS receipt required, not a prepared plan')
    m=SimpleNamespace(need=A.need,decode=A.decode)
    stage=SimpleNamespace(get=objects.get,op=SimpleNamespace(k=lambda *args:A.encode(objects.get(args[1],args[2]))))
    refs,storage=topology.snapshot(m,stage,actual,target)
    ca={'File':actual['ca_file'],'SHA256':actual['ca_sha256']};A.read(ca)
    typed=topology.MinIOProviderTopology('original-minio-provider-topology-data.v1',target['InstallationID'],A.NS,target['NamespaceUID'],
        actual['endpoint'],actual['server_name'],topology.FilePin(**ca),actual['spki_sha256'],actual['leaf_sha256'],topology.FilePin(**receipt_pin),
        refs,actual['container'],actual['container_id'],actual['image_id'],storage)
    topo=A.retain(directory/'recorded-provider-topology.data.json',asdict(typed))
    cluster=objects.get('namespace','kube-system');domain='cluster:'+cluster['metadata']['uid']
    nodes=[v for (kind,_,_),v in objects.items.items() if kind=='Node']
    kinds={'k3s' if 'k3s' in n['status']['nodeInfo']['kubeletVersion'] else 'kubernetes' for n in nodes}
    A.need(len(kinds)==1,'one recorded source orchestrator required')
    identity=A.retain(directory/'functional-domain-identity.json',{'KubernetesAPI':plan['KubernetesAPI'],'KubernetesCASHA256':plan['KubernetesCASHA256'],'KubeSystemUID':cluster['metadata']['uid']})
    A.retain(directory/'functional-failure-domains.json',{'schema_version':'system-backup-original-failure-domains.v1','origin_installation_id':target['InstallationID'],
        'registry_version':'initial-functional-domains-v1','history':[{'sequence':1,'domain_id':domain,'identity_sha256':identity['SHA256'],'state':'active','previous_sha256':''}]})
    risks=sorted(['attestation_missing','same_failure_domain','source_overlap','artifact_credential_source_dependent','kek_source_dependent','signing_key_source_dependent','catalog_source_dependent'])
    reference='isolated-policy-'+A.sha(target['InstallationID'].encode())[:24]
    policy=A.retain(directory/'functional-restore-target-policy.json',{'schema_version':'original-functional-restore-target-policy.v1','installation_id':target['InstallationID'],
        'reference':reference,'source_namespace':A.NS,'source_namespace_uid':target['NamespaceUID'],'source_database':target['Database'],'source_database_server_uuid':target['ServerUUID'],
        'target_namespace_prefix':'cm-drill-','target_database_prefix':'cm_drill_','target_kind':'isolated_drill','admin_policy':'replace_bootstrap_with_source_admin',
        'start_policy':'stopped_tasks_disabled','source_namespace_reuse':'forbidden','source_database_reuse':'forbidden','source_volume_reuse':'forbidden',
        'required_observation_schema':'system-backup-b-restore-target.v1','owned_target_topology':topo,'failure_domain_identity':identity})
    value={'installation_id':target['InstallationID'],'revision':'initial-functional-v1','source_orchestrator':next(iter(kinds)),'source_profile':'cluster','target_class':'same-cluster-copy',
        'target_risks':risks,'target_failure_domain_id':domain,'restore_target_ref':reference,'restore_target_sha256':policy['SHA256']}
    A.retain(directory/'configured-execution-profile.json',value)
    return value


def compile_data(inputs,directory,mirror):
    A.need(inputs['Version']=='p2-ready-initial-producers.v1','named original producer inputs required')
    # The helper is shipped by exact Git blob; its pin is in the package sums.
    helper=module_from_pin(inputs['CompleteInputsHelper'])
    plan,sql,operation,coordinates,writer,pki,observer,worker_def=(A.obj(inputs[k]) for k in
        ['Plan','SQLMaterials','SQLOperation','Coordinates','WriterSelection','RelayPKI','ObserverReceipt','WorkerDefinition'])
    objects=RecordedObjects(inputs['KubernetesObjects'])
    profile=configured_profile(inputs,objects,plan,directory)
    target=plan['Target']
    A.need(target['Namespace']==A.NS and coordinates['Namespace']==A.NS and coordinates['NamespaceUID']==target['NamespaceUID'] and
           coordinates['InstallationID']==profile['installation_id']==target['InstallationID'],'same original installation DATA required')
    A.need(operation['ServerUUID']==target['ServerUUID']==sql['server_uuid'] and operation['Database']==target['Database']==sql['database'],'same actual SQL role producer required')
    host,worker,staging=current_host(objects,plan,worker_def)
    app=objects.get('deployment','clawmanager-app')
    A.need(app['metadata']['uid']=='8ebd4d4c-57b6-4a82-b310-fae596681a4e','original App changed')
    # New PKI must be issued into the final mount coordinates. Do not relocate
    # signed manifests or silently reinterpret old keys as a renewed receipt.
    for receipt,keys in [(pki,['CA','IssuerKey','ServerCertificate','ServerKey']), (observer,['CA','ClientCertificate','ClientKey'])]:
        for key in keys:
            A.read(receipt[key]);A.need(Path(receipt[key]['File']).is_relative_to(mirror),'issue genuine PKI in the final private runtime mirror')
    roles={x['Role']:x for x in operation['Accounts']}
    source=sql['files']['mysql-source.dsn'];A.read(source)
    ca={'File':sql['source_tls']['ca_file'],'SHA256':sql['source_tls']['ca_sha256']};A.read(ca)
    # These are explicit location DATA copies, not rewritten native receipts.
    mirror.mkdir(mode=0o700,exist_ok=True)
    source_copy=A.retain(mirror/'mysql-source.dsn',A.read(source))
    ca_copy=A.retain(mirror/'database-ca.pem',A.read(ca))
    trust_dir=mirror/'original-relay-trust';trust_dir.mkdir(mode=0o700,exist_ok=True)
    plan_copy=A.retain(trust_dir/'plan.json',A.read(inputs['Plan']))
    public_copy=A.retain(trust_dir/'issuer.public',A.read(inputs['SourceIssuerPublic']))
    trust={'PKI':pki,'CoreFields':{'original_relay_enrollment':{'Plan':plan_copy,'IssuerPublic':public_copy,'Enrollment':A.obj(inputs['Enrollment'])},
        'control_url':pki['Endpoint'],'tls':{'issuer_certificate':pki['CA']['File'],'issuer_key':pki['IssuerKey']['File'],
            'server_certificate':pki['ServerCertificate']['File'],'server_key':pki['ServerKey']['File']}}}
    A.need(pki['DeploymentUID']==host['DeploymentUID'],'relay PKI controller mismatch')
    # Only the Core comparison DATA uses refreshed observer pins. The retained
    # native writer selection is never overwritten or re-labelled as renewed.
    observed_writer=copy.deepcopy(writer)
    for key,source_key in [('ObserverCA','CA'),('ObserverCertificate','ClientCertificate'),('ObserverKey','ClientKey')]:observed_writer[key]=observer[source_key]
    for key,kind in [('SharedRuntimeEndpoints','shared'),('WholePodEndpoints','whole'),('StoppedProEndpoints','stopped-pro')]:
        observed_writer[key]={e['Node']:e['Endpoint'] for e in observer['Endpoints'] if e['Kind']==kind}
    agent=A.retain(mirror/'original-agent-control-token',A.read(writer['AgentCredential']))
    selected_agent_ca=runtime_agent_ca(inputs,objects,writer,plan)
    agent_ca=A.retain(mirror/'original-agent-ca.pem',A.read(selected_agent_ca))
    observed_writer.update(AgentCredential=agent,AgentCA=agent_ca)
    app_image=immutable_image(inputs['AppImage']);worker_image=immutable_image(inputs['WorkerImage'])
    container=app['spec']['template']['spec']['containers']
    A.need(len(container)==1 and container[0]['image']==app_image['reference'],'current App must use the selected immutable business image')
    business={'deployment/'+A.NS+'/clawmanager-app':[dict(Container=container[0]['name'],Image=app_image['reference'],ConfigDigest=app_image['config_digest'],BuildCommit=app_image['commit'])]}
    A.retain(directory/'new-image.result.json',{'version':'p2-recorded-image-DATA.v1','images':{'app':app_image,'worker':worker_image},'SourcePins':{'App':inputs['AppImage'],'Worker':inputs['WorkerImage']},'NativeQualified':False})
    # Existing runtime-image exporter uses these actual manifest filenames.
    startup=A.obj(inputs['RuntimeStartupInputs']);runtime_images={}
    A.need(startup['Version']=='original-runtime-startup-image-inputs.v1','qualified original startup inputs required')
    for image in startup['Images']:
        name=Path(image['Manifest']['File']).name
        kind=name.removesuffix('-manifest.json')
        A.need(kind in ['openclaw','hermes'] and kind not in runtime_images,'finite runtime image roster required')
        raw=A.read(image['Manifest']);A.read(image['Config'])
        runtime_images[kind]={'reference':'10.130.14.23:5000/'+kind+'-lite@sha256:'+A.sha(raw)}
    A.need(set(runtime_images)=={'openclaw','hermes'},'both original runtime images required')
    A.retain(directory/'runtime-images.result.json',{'version':'p2-recorded-runtime-image-DATA.v1','images':runtime_images,'Source':inputs['RuntimeStartupInputs'],'NativeQualified':False})
    host_result={'host':host,'accounts':{'worker':{'Name':worker['metadata']['name'],'UID':worker['metadata']['uid']}},
        'pvc_uids':{'staging':staging['metadata']['uid']},'runtime_input_pins':{'mysql-source.dsn':source_copy,'database-ca.pem':ca_copy},
        'control_service':{'SelectedURL':pki['Endpoint']},'RecordedInputsOnly':True}
    A.retain(directory/'host-observer.result.json',host_result)
    def read(file,expected=None,**kwargs):
        path=Path(file);raw=path.read_bytes()
        if expected:A.need(A.sha(raw)==expected,'original bytes changed')
        return raw
    m=SimpleNamespace(NS=A.NS,STAGING='/var/lib/system-backup/staging',need=A.need,decode=A.decode,read=read,digest=A.sha,
        encoded=A.encode,pinned=lambda pin,**kwargs:A.read(pin),pin=lambda path,**kwargs:{'File':str(path),'SHA256':A.sha(Path(path).read_bytes())})
    def recorded_get(*args):
        # Minimal read-only selector used by the existing pure DATA projector.
        args=list(args);ns=A.NS
        if args[:1]==['-n']:ns=args[1];args=args[2:]
        A.need(args[:1]==['get'],'recorded projection cannot perform an operation')
        if args[1]=='pods':
            labels=dict(pair.split('=',1) for pair in args[args.index('-l')+1].split(','))
            return A.encode({'items':objects.pods(ns,labels)})
        return A.encode(objects.get(args[1],args[2],ns))
    stage=SimpleNamespace(directory=directory,prefix=A.CONTROLLER.removesuffix('-controller'),scope={'app_deployment_uid':app['metadata']['uid']},
        get=objects.get,runtime_mirror=lambda:mirror,check_host=lambda h:A.need(h==host,'recorded host changed'),
        common=lambda:([],{},plan,sql))
    stage.op=SimpleNamespace(k=recorded_get,prepare_relay_runtime_trust=lambda:trust,
        sql_role_inputs=lambda:{'roles':{'source':{'username':roles['source']['User'],'dsn':source_copy}}})
    effective=A.obj(inputs['EffectiveAppConfig'])
    assembly=SimpleNamespace(original_app_environment=lambda *args:effective['WorkspaceRoot'].encode())
    envelope=A.obj(inputs['RuntimeIssuers']);issuers=A.decode(base64.b64decode(envelope['Record'],validate=True))
    forward=base64.b64encode(A.read(issuers['Issuers']['forward_execution']['PublicKey'])).decode()
    source_public=base64.b64encode(A.read(inputs['SourceIssuerPublic'])).decode()
    core,out,_,_=helper.source_core(m,stage,assembly,coordinates,observed_writer,profile,pki,forward)
    uri=urlsplit(observer['ClientURI'])
    A.need(uri.scheme=='spiffe' and uri.hostname,'actual observer trust domain required')
    core['trust_domain']=uri.hostname
    core['source_tls']={**sql['source_tls'],'ca_file':ca_copy['File'],'ca_sha256':ca_copy['SHA256']}
    api=A.obj(inputs['SourceAPI']);api_selection={**api,'scope':{'ServiceAccount':api['service_account']}}
    redis=A.obj(inputs['Redis']);keeper=A.obj(redis['KeeperSelection']);policy=A.obj(redis['Policy'])
    redis_selection={'source_mount':{'GrantFile':str(out/'redis-source.grant.json'),'GrantSHA256':'','Issuer':source_public,
        'CredentialFile':keeper['ReaderCredential']['File'],'CredentialSHA256':keeper['ReaderCredential']['SHA256'],
        'Redis':{'Address':keeper['ServerName']+':'+str(keeper['Port']),'ServerName':keeper['ServerName'],'CAFile':keeper['CA']['File'],'CASHA256':keeper['CA']['SHA256']},
        'Objects':None,'RedisScope':{'ID':policy['Policy']['Source']['ID'],'ServerID':policy['ServerID'],'Database':policy['Policy']['DB'],'KeyPrefix':''},
        'ObjectPrefixes':None,'RedisPrefixes':policy['Policy']['Prefixes'],'RedisExcludedPrefixes':policy['ExcludePrefixes']},'capture_policy':policy}
    actors={}
    for part,suffix in [('deployment_resources','resources'),('secret_bundle','secrets')]:
        sa=objects.get('serviceaccount',stage.prefix+'-'+suffix);actors[part]={'Name':sa['metadata']['name'],'UID':sa['metadata']['uid']}
    material=helper.material_template(m,stage,assembly,core,out,host,app,coordinates,redis_selection,A.obj(inputs['MinIO']),api_selection,source_public,operation,
        selected_data={'EffectiveAppConfig':effective,'ResourceActors':actors,'TeamWriterImages':business})
    controller={'Namespace':A.NS,'NamespaceUID':target['NamespaceUID'],**host}
    value={'Version':'original-initial-source-author-inputs.v1','Deployment':core,'Materials':material,'Profile':profile,'Controller':controller,
        'Connections':[],'RuntimeAgent':{'Operations':['backup_capabilities_read','gateway_state_read'],'ScopeSHA256':'','CA':agent_ca,'Credential':agent},
        'PartsVersion':'original-first-source.v1','SourceWritersVersion':'original-first-source.v1','RedisSourcesVersion':'original-first-source.v1',
        'NotBefore':inputs['NotBefore'],'Until':inputs['Until']}
    config=A.retain(directory/'configuration-data.json',value)
    assembly_inputs={key:inputs[key] for key in ['MinIO','Redis','SourceAPI','SQLOperation','RuntimeIssuers','SourceIssuerPublic','ObserverReceipt']}
    assembly_inputs.update(Version='p2-installation-assembly-inputs.v1',ConfigurationData=config,SourceDSN=source_copy,
        ControlDSN=sql['files']['mysql-control_sql.dsn'],DatabaseCA=ca_copy)
    return {'ConfigurationData':config,'AssemblyInputs':A.retain(directory/'assembly-inputs.json',assembly_inputs),
            'NativeOutputDirectory':str(out),'NativeAuthorCalled':False,'ProviderOrRedisApplied':False,'BackupReady':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs-file');p.add_argument('--inputs-sha256')
    p.add_argument('--prepare-index',action='store_true')
    p.add_argument('--read-image-data',action='store_true');p.add_argument('--image-reference')
    for key in ['raw-index','relay-receipt','observer-receipt','app-image-data','worker-image-data','source-api','runtime-issuers','coordinates-receipt','writer-receipt','runtime-agent-tls','runtime-agent-rotation']:
        p.add_argument('--'+key+'-file');p.add_argument('--'+key+'-sha256')
    p.add_argument('--output-directory',type=Path,required=True);p.add_argument('--runtime-mirror',type=Path)
    args=p.parse_args()
    os.umask(0o077)
    A.need(not (args.prepare_index and args.read_image_data),'one preparation action required')
    for d in [args.output_directory]+([args.runtime_mirror] if not args.prepare_index and not args.read_image_data else []):
        A.need(d is not None,'runtime mirror required for configuration DATA compilation')
        A.need(d.is_absolute() and d.resolve(strict=True)==d and d.is_dir() and
               (os.name!='posix' or d.stat().st_mode & 0o077==0),'existing real private DATA directories required')
    if args.read_image_data:result=read_image_data(args.image_reference,args.output_directory)
    elif args.prepare_index:result={'ReadyInputs':prepare_index(args),'NativeAuthorCalled':False,'BackupReady':False}
    else:
        A.need(args.inputs_file and args.inputs_sha256,'ready producer file/pin required')
        result=compile_data(A.obj({'File':args.inputs_file,'SHA256':args.inputs_sha256}),args.output_directory,args.runtime_mirror)
    print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError) as error:
        raise SystemExit('P2_CONFIGURATION_DATA_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))
