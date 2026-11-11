#!/usr/bin/env python3
"""This installation's DATA assembly and Longhorn successor handoff.

No network or mutation of Kubernetes/SQL. Native owners authenticate all DATA
when the rendered commands are eventually run. A local result is never a hold,
issued grant, loaded certificate, enabled controller or completed backup.
"""
import argparse
import base64
import copy
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile

SNAPSHOT_SHA = 'dfaf71f6b78b0dc852578c57a052a7bbc5329d442db219062be48b131a52fcb1'
NS = 'clawmanager-sbk-validation-system'
TENANT = 'clawmanager-sbk-validation-user-1'
CONTROLLER = 'sbk-d4f51b83b57e-controller'
CONTROLLER_UID = 'e4e27f27-8f02-40ab-8c62-09f2ffa3fafa'
PURPOSES = ['control_sql', 'source_api', 'source_objects', 'source_redis', 'source_sql']
KNOWN = {
    'MinIO': {'File': '/root/sbk/p2-minio-prepare.9vnemhVi/connection-continuation/minio-source-fragment.json', 'SHA256': 'c3b4eae48b3d78c12872742be55e6bc95f11bc9e594c83b8697728edc020ede8'},
    'Redis': {'File': '/root/sbk/p2-redis-connection.b5dQ12Lt/redis-source-fragment.json', 'SHA256': '8451e409dbc331e249b2824ec34be3a0d62c9ceb1de4151f813b9e26f7ffa43d'},
    'SourceAPI': {'File': '/root/sbk/p2-api-runtime-inputs.WWN62yPS/source-api-fragment.json', 'SHA256': '83fa7d8304c986e767387f53a4bcee1ee412dfef50e4305cba7faf54418a2142'},
    'RuntimeIssuers': {'File': '/root/sbk/p2-api-runtime-inputs.WWN62yPS/runtime-issuers/original-runtime-issuers.json', 'SHA256': 'e9b858488514ad96bd9b16f1ae26ddf289439c4b73d50f6ea63c041c52619466'},
}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def encode(value):
    # DATA only. Do not reserialize native signed records or Go canonical pins.
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def read(pin, maximum=8 << 20):
    need(isinstance(pin, dict) and set(pin) == {'File', 'SHA256'} and
         re.fullmatch('[a-f0-9]{64}', pin['SHA256']) is not None, 'complete raw-byte pin required')
    path = Path(pin['File'])
    need(path.is_absolute() and not path.is_symlink() and path.resolve(strict=True) == path and
         path.is_file() and 0 < path.stat().st_size <= maximum, 'regular bounded original file required')
    need(os.name != 'posix' or path.stat().st_mode & 0o077 == 0, 'private runtime input permissions required')
    raw = path.read_bytes()
    need(sha(raw) == pin['SHA256'], 'original bytes changed: ' + path.name)
    return raw


def obj(pin):
    return decode(read(pin))


def retain(path, value):
    raw = value if isinstance(value, bytes) else encode(value)
    need(not path.is_symlink() and path.parent.resolve(strict=True) == path.parent, 'real output directory required')
    if path.exists():
        need(path.is_file() and path.read_bytes() == raw, 'existing DATA changed; retain original operation')
    else:
        with path.open('xb') as stream:
            os.chmod(path, 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    return {'File': str(path), 'SHA256': sha(raw)}


def connection(value, purpose):
    need(set(value) == {'Purpose', 'Endpoint', 'Account', 'ServerUUID', 'Database', 'CA', 'Credential', 'IdentitySHA256', 'ScopeSHA256'} and
         value['Purpose'] == purpose and value['Account'] and
         value['IdentitySHA256'] == value['ScopeSHA256'] == '', 'initial connection shape or purpose changed')
    read(value['CA']); read(value['Credential'])
    return copy.deepcopy(value)


def assemble(inputs, now):
    """Complete the existing native author definition from real pinned producers.

    ConfigurationData is the existing initial-complete-inputs producer's full
    Deployment/Materials/Profile/Controller DATA, not a redacted snapshot.
    Native author validation is still required after this projection.
    """
    need(inputs['Version'] == 'p2-installation-assembly-inputs.v1', 'assembly input version')
    original = obj(inputs['ConfigurationData'])
    need(original['Version'] == 'original-initial-source-author-inputs.v1', 'existing complete configuration DATA required')
    value = copy.deepcopy(original)
    core, materials = value['Deployment'], value['Materials']
    need(core['namespace'] == NS and core['controller_owner'] == CONTROLLER_UID and
         value['Controller']['Deployment'] == CONTROLLER and value['Controller']['DeploymentUID'] == CONTROLLER_UID,
         'selected installation controller changed')
    need(core['runtime_sources']['shared_runtime_protocol'] == 'shared-container-freeze.v1' and
         isinstance(core['runtime_sources']['lease_participants'], list), 'explicit complete participant census required')
    minio, redis, api = (obj(inputs[key]) for key in ['MinIO', 'Redis', 'SourceAPI'])
    need(minio['Version'] == 'validation-p2-minio-source-data.v1' and redis['Version'] == 'validation-p2-redis-source-data.v1', 'actual connection producer versions required')
    operation = obj(inputs['SQLOperation'])
    need(operation['Database'] == core['source_database'] and operation['ServerUUID'] == core['source_server_uuid'], 'same original SQL peer required')
    roles = {a['Role']: a for a in operation['Accounts']}
    need(len(roles) == len(operation['Accounts']) and all(r in roles for r in ['control_sql', 'source']), 'distinct actual native SQL roles required')
    def sql(role, purpose, credential):
        account = roles[role]
        read(credential); read(inputs['DatabaseCA'])
        return {'Purpose': purpose, 'Endpoint': 'mysql+tls://' + operation['Address'], 'Account': account['User'] + '@' + account['Host'],
                'ServerUUID': operation['ServerUUID'], 'Database': operation['Database'], 'CA': inputs['DatabaseCA'], 'Credential': credential,
                'IdentitySHA256': '', 'ScopeSHA256': ''}
    value['Connections'] = [sql('control_sql', 'control_sql', inputs['ControlDSN']), api['connection'], minio['Connection'], redis['Connection'], sql('source', 'source_sql', inputs['SourceDSN'])]
    value['Connections'] = [connection(c, purpose) for c, purpose in zip(value['Connections'], PURPOSES)]
    need(len({c['Credential']['File'] for c in value['Connections']}) == 5, 'five distinct purpose credentials required')
    need(core['source_dsn_file'] == inputs['SourceDSN']['File'], 'Core must consume the selected read-only source DSN')
    keeper, policy = obj(redis['KeeperSelection']), obj(redis['Policy'])
    need(keeper['Native']['Policy'] == policy and core['redis_read_keepers'] == [keeper], 'actual Redis keeper/policy successor required')
    native = redis['NativeReceipt']
    need(native['State'] == 'native_tls_and_accounts_read_back_not_a_hold' and native['WriterSelection'] == redis['WriterSelection'], 'Redis native finalize must precede assembly')
    read(redis['WriterSelection'])
    need(materials['Redis']['CredentialFile'] == keeper['ReaderCredential']['File'] and
         materials['Redis']['CredentialSHA256'] == keeper['ReaderCredential']['SHA256'] and
         materials['Discovery']['Redis'] == policy, 'capture Redis source must consume the native successor')
    need(all(materials['Objects'].get(k) == v for k, v in minio['MaterialsObjectsData'].items()), 'capture MinIO connection differs from actual TLS fragment')
    discovery = materials['Discovery']
    need(discovery['SourceAPITokenSHA256'] == api['connection']['Credential']['SHA256'] and
         discovery['SourceAPIServiceAccountUID'] == api['connection']['Account'] and
         discovery['SourceAPI']['TokenFile'] == api['connection']['Credential']['File'], 'source API capture binding mismatch')
    envelope = obj(inputs['RuntimeIssuers'])
    record = decode(base64.b64decode(envelope['Record'], validate=True))
    forward = read(record['Issuers']['forward_execution']['PublicKey'])
    source = read(inputs['SourceIssuerPublic'])
    need(len(forward) == len(source) == 32 and forward != source, 'independent real purpose issuer required')
    need(core['forward_grant']['public_key_base64'] == core['recovery_grant']['public_key_base64'] == base64.b64encode(forward).decode() and
         discovery['Issuer'] == base64.b64encode(source).decode(), 'purpose key crossed with enrollment key')
    observer = obj(inputs['ObserverReceipt'])
    before, after = (datetime.datetime.fromisoformat(observer[k].replace('Z', '+00:00')) for k in ['NotBefore', 'NotAfter'])
    until = datetime.datetime.fromisoformat(value['Until'].replace('Z', '+00:00'))
    need(before <= now < until <= after and until.timestamp() <= api['token_expires_unix'], 'real renewed observer/API validity must cover installation window')
    shared = core['runtime_sources']['shared_runtime_observer']
    for name, pin in [('CA', observer['CA']), ('Certificate', observer['ClientCertificate']), ('Key', observer['ClientKey'])]:
        read(pin)
        need(shared[name + 'File'] == pin['File'] and shared[name + 'SHA256'] == pin['SHA256'], 'Core mixes observer generations')
    need(materials['DeploymentConfigSHA256'] == materials['CaptureGrantSHA256'] == '' and
         'longhorn_hold' not in core['runtime_sources'], 'initial author must precede taskless Longhorn successor')
    return value


def longhorn_successor(previous_pin, receipt_pin, host_definition_pin, observer_definition_pin, observer_receipt_pin):
    previous, receipt = obj(previous_pin), obj(receipt_pin)
    need(receipt['Version'] == 'original-instance-mount-materials-receipt.v1' and receipt['SelectionSHA256'] == previous_pin['SHA256'], 'mount author must consume the exact previous selection')
    for key in ['Deployment', 'MaterialsTemplate', 'SourceSelection', 'LonghornHoldMaterials']:
        read(receipt[key])
    selected, core, material = (obj(receipt[key]) for key in ['SourceSelection', 'Deployment', 'MaterialsTemplate'])
    need(selected['Deployment'] == receipt['Deployment'] and selected['MaterialsTemplate'] == receipt['MaterialsTemplate'] and
         material['DeploymentConfigSHA256'] == receipt['Deployment']['SHA256'], 'Longhorn successor Core/template pins differ')
    need({k:v for k,v in selected.items() if k not in ['Deployment', 'MaterialsTemplate']} ==
         {k:v for k,v in previous.items() if k not in ['Deployment', 'MaterialsTemplate']}, 'mount handoff changed unrelated source selection')
    old_core = obj(previous['Deployment'])
    without_hold = copy.deepcopy(core)
    hold = without_hold['runtime_sources'].pop('longhorn_hold')
    need(without_hold == old_core and hold['Materials'] == [receipt['LonghornHoldMaterials']], 'only native Longhorn successor may change Core')
    observed = obj(observer_receipt_pin)
    shared = core['runtime_sources']['shared_runtime_observer']
    need(all(shared[name+'File'] == observed[key]['File'] and shared[name+'SHA256'] == observed[key]['SHA256']
             for name, key in [('CA','CA'), ('Certificate','ClientCertificate'), ('Key','ClientKey')]), 'Node/Core observer generation mismatch')
    definition = obj(host_definition_pin)
    definition.update(PKIDefinition=observer_definition_pin, PKIReceipt=observer_receipt_pin, LonghornVolumes=receipt['LonghornHoldMaterials'])
    # These DATA selectors feed the unchanged signing/host/controller owners.
    # No successor is selected using mtime, newest directory or an old Core.
    return {'Version': 'p2-longhorn-successor-handoff.v1', 'ParentSelection': previous_pin,
            'MountReceipt': receipt_pin, **{k: receipt[k] for k in ['Deployment','MaterialsTemplate','SourceSelection','LonghornHoldMaterials']},
            'HostDefinition': definition, 'FieldVerified': False, 'BackupReady': False}


def base_observer_definition(original_pin,definition_pin,receipt_pin):
    original=obj(original_pin);obj(definition_pin);receipt=obj(receipt_pin)
    need(original['Version']=='original-observer-host-deployment.v1' and
         original.get('LonghornVolumes',{'File':'','SHA256':''})=={'File':'','SHA256':''} and
         not original.get('LonghornSourceRegistry'),'only original pre-hold host definition can load the new base PKI')
    for key in ['CA','ClientCertificate','ClientKey']:read(receipt[key])
    return dict(original,PKIDefinition=definition_pin,PKIReceipt=receipt_pin)


def audit_snapshot(raw):
    need(sha(raw) == SNAPSHOT_SHA, 'approved offline snapshot bytes changed')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        members = archive.getmembers()
        need(len(members) == 25 and all(m.isfile() and '/' not in m.name and '\\' not in m.name and m.size <= 32 << 20 for m in members) and
             len({m.name for m in members}) == len(members), 'bounded flat snapshot required')
        files = {m.name: decode(archive.extractfile(m).read()) for m in members}
    index = files['capture-index.json']
    need(index['errors'] == [], 'snapshot collection incomplete')
    return files


def freeze(snapshot, directory):
    files = audit_snapshot(snapshot.read_bytes())
    return retain(directory / 'offline-candidate.json', {
        'Version': 'p2-offline-candidate.v1', 'SnapshotSHA256': SNAPSHOT_SHA,
        'InstallationNamespace': NS, 'TenantNamespace': TENANT, 'Controller': CONTROLLER, 'ControllerUID': CONTROLLER_UID,
        'Connections': PURPOSES, 'RetainedProducers': KNOWN,
        'RemotePrivateInputs': files['capture-index.json']['remote_private_inputs'],
        'Order': ['actual-identity-and-token-review', 'exact-additive-provider-read-access', 'verify-or-install-existing-vault-owner', 'renew-observer-create-only',
                  'native-base-host-materials-and-Node-PKI-loading',
                  'assemble-complete-initial-source-data', 'native-author-initial-source-inputs', 'native-prepare-mount-materials-AuthorLonghornHold',
                  'select-successor-Core-template-source-and-hold-together', 'native-source-facts-and-signing',
                  'native-host-materials-with-successor-and-new-PKI', 'install-Node-bundles-and-check-mTLS',
                  'native-disabled-config-and-controller-consumption', 'field-admission-and-whole-backup'],
        'ObserverRenewalRequired': True, 'CompleteExecutionReady': False,
        'MissingRealExecutionInputs': ['qualified-worker-release-selection', 'renewed-private-PKI-and-loaded-Node-identities',
            'actual-C1-native-capture-consumption-functional-and-evidence-outputs',
            'actual-disabled-registration-enable-and-normal-handover-outputs', 'this-installation-publication-owner-context'],
        'Vault': {'Repository': 'clawmanager-backup-vault', 'ObservedTags': files['registry-clawmanager-backup-vault-tags.json'], 'InstalledOrUsableVerified': False},
        'FieldVerified': False, 'ControllerEnabled': False, 'BackupReady': False})


def waiting_controller_patch(deployment, binary_pin):
    """Upgrade only the waiting executable, never publish an activation marker.

    The live raw deployment must be supplied at runtime. Redacted command
    hashes are deliberately insufficient for its UID/resourceVersion CAS.
    """
    need(deployment['metadata']['name'] == CONTROLLER and deployment['metadata']['uid'] == CONTROLLER_UID and
         deployment['metadata']['namespace'] == NS and deployment['metadata'].get('resourceVersion'), 'actual selected controller deployment required')
    need(binary_pin['File'] == '/run/system-backup/bin/system-backup-v2-controller' and
         re.fullmatch('[a-f0-9]{64}', binary_pin['SHA256']) is not None, 'public-v1 controller binary at existing input mount required')
    containers = deployment['spec']['template']['spec']['containers']
    indices = [i for i,c in enumerate(containers) if c['name'] == 'controller']
    need(len(indices) == 1, 'one original controller container required')
    index=indices[0]; c=containers[index]
    need(any(x['name']=='inputs' and x['mountPath']=='/run/system-backup' and x.get('readOnly') is True for x in c.get('volumeMounts',[])), 'existing controller read-only input mount required')
    env={x['name']:x.get('value') for x in c.get('env',[])}
    need(env.get('SYSTEM_BACKUP_ENABLED') == 'false' and
         env.get('SYSTEM_BACKUP_EXECUTION_PROTOCOL') == 'public-v1', 'only pre-activation public-v1 controller may receive this patch')
    old_command=c.get('command',[])
    need(any('controller.env.ready' in x or 'f=/run/system-backup/runtime/controller.env' in x and '$f.ready' in x for x in old_command) and any('/usr/local/bin/system-backup-v2-controller' in x for x in old_command), 'original waiting controller entry point required')
    # Hash check precedes the original waiting shell. No new environment,
    # marker, DB credential or admission path is introduced by this overlay.
    command=[x.replace('/usr/local/bin/system-backup-v2-controller',binary_pin['File']) for x in old_command]
    need(command[0] in ['/bin/sh','sh'] and command[1] in ['-c','-ec'] and len(command)==3, 'exact existing waiting shell required')
    command[2] = "test \"$(sha256sum /run/system-backup/bin/system-backup-v2-controller | cut -d ' ' -f 1)\" = " + binary_pin['SHA256'] + ' || exit 1; ' + command[2]
    return [{'op':'test','path':'/metadata/uid','value':CONTROLLER_UID},
            {'op':'test','path':'/metadata/resourceVersion','value':deployment['metadata']['resourceVersion']},
            {'op':'test','path':'/spec','value':deployment['spec']},
            {'op':'replace','path':'/spec/template/spec/containers/'+str(index)+'/command','value':command}]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    f = sub.add_parser('freeze'); f.add_argument('--snapshot', type=Path, required=True)
    a = sub.add_parser('assemble'); a.add_argument('--inputs-file', required=True); a.add_argument('--inputs-sha256', required=True)
    h = sub.add_parser('longhorn-handoff')
    for name in ['previous-selection', 'mount-receipt', 'host-definition', 'observer-definition', 'observer-receipt']:
        h.add_argument('--'+name+'-file', required=True); h.add_argument('--'+name+'-sha256', required=True)
    c = sub.add_parser('controller-waiting-patch')
    c.add_argument('--deployment-file',required=True); c.add_argument('--deployment-sha256',required=True)
    c.add_argument('--binary-sha256',required=True)
    b=sub.add_parser('base-observer-definition')
    for name in ['host-definition','observer-definition','observer-receipt']:
        b.add_argument('--'+name+'-file',required=True);b.add_argument('--'+name+'-sha256',required=True)
    for command in [f, a, h, c, b]: command.add_argument('--output-directory', type=Path, required=True)
    args = p.parse_args()
    os.umask(0o077)
    directory = args.output_directory
    need(directory.is_absolute() and directory.resolve(strict=True) == directory and directory.is_dir(), 'existing private absolute output directory required')
    need(os.name != 'posix' or directory.stat().st_mode & 0o077 == 0, 'private output directory required')
    if args.action == 'freeze':
        result = freeze(args.snapshot, directory)
    elif args.action == 'assemble':
        value = assemble(obj({'File': args.inputs_file, 'SHA256': args.inputs_sha256}), datetime.datetime.now(datetime.timezone.utc))
        result = retain(directory / 'initial-source-inputs.json', value)
    elif args.action == 'longhorn-handoff':
        pins = [{'File': getattr(args, k+'_file'), 'SHA256': getattr(args, k+'_sha256')} for k in ['previous_selection','mount_receipt','host_definition','observer_definition','observer_receipt']]
        result = retain(directory / 'longhorn-successor-handoff.json', longhorn_successor(*pins))
    elif args.action=='base-observer-definition':
        pins=[{'File':getattr(args,k+'_file'),'SHA256':getattr(args,k+'_sha256')} for k in ['host_definition','observer_definition','observer_receipt']]
        result=retain(directory/'base-observer-host.definition.json',base_observer_definition(*pins))
    else:
        live=obj({'File':args.deployment_file,'SHA256':args.deployment_sha256})
        patch=waiting_controller_patch(live,{'File':'/run/system-backup/bin/system-backup-v2-controller','SHA256':args.binary_sha256})
        result=retain(directory / 'controller-waiting.patch.json',patch)
    print(json.dumps({'state':'p2_local_DATA_only_requires_original_owner_validation', 'output':result, 'backup_ready':False}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        raise SystemExit('P2_ASSEMBLY_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))
