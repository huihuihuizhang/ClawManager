#!/usr/bin/env python3
"""Closed native DATA/PKI steps, with create-only send journals.

Default is command review only. This tool never enables the controller, admits
a task, restarts a workload or replaces an unknown native operation.
"""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
from urllib.parse import urlsplit


def assembly():
    p = Path(__file__).with_name('assemble-p2-installation-candidate.py')
    spec = importlib.util.spec_from_file_location('p2_assembly', p)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


A = assembly()
STAGES = {
    'observer-issue': ('system-backup-original-observer-pki', [], 'ObserverDefinition'),
    'base-host-materials': ('system-backup-observer-deployment-materials', ['--mode', 'host-materials'], 'BaseHostDefinition'),
    'initial-source': ('system-backup-first-install-materials', ['author-initial-source-inputs'], 'InitialDefinition'),
    'mount': ('system-backup-source-registries', ['prepare-mount-materials'], 'MountLayouts'),
    'facts': ('system-backup-source-registries', ['produce-facts'], None),
    'host-materials': ('system-backup-observer-deployment-materials', ['--mode', 'host-materials'], 'HostDefinition'),
}


def owner_arguments(owner):
    result = []
    for key, flag, digest in [('Plan','plan',True), ('IssuerPublic','issuer-public',True),
                             ('Enrollment','enrollment-pin',True), ('Kubeconfig','kubeconfig',True),
                             ('InstallerDSN','dsn',False), ('DatabaseCA','database-ca',False),
                             ('AdminPassword','local-admin-password',False)]:
        A.read(owner[key])
        result += ['--'+flag+'-file', owner[key]['File']]
        if digest: result += ['--'+flag+'-sha256', owner[key]['SHA256']]
    plan = A.obj(owner['Plan'])
    A.need(plan['Target']['Namespace'] == A.NS, 'this installation only')
    return result


def check_host_source_core(definition, handoff):
    # DATA cross-check only; the original host owner authenticates the actual
    # V2 signature, capture consumer and live tenant provenance independently.
    refs=definition['LonghornSourceRegistry']
    selected=refs['Registry']
    record=A.obj({'File':selected['RecordFile'],'SHA256':selected['RecordSHA256']})
    A.read(refs['CaptureConsumer']); A.read(refs['CaptureConsumerPin'])
    A.need(record['SchemaVersion']=='system-backup-original-bootstrap-source-registries.v2' and
           record['Source']['Deployment']==handoff['Deployment'], 'host signed source registry selects an old Core')
    material=A.obj(record['Source']['Materials'])
    A.need(material['DeploymentConfigSHA256']==handoff['Deployment']['SHA256'], 'host final capture material selects an old Core')


def stage_argv(bundle, stage):
    A.need(bundle['Version'] == 'p2-native-candidate-operations.v1' and stage in STAGES, 'closed native step required')
    binary, prefix, input_key = STAGES[stage]
    tool = bundle['Tools'][binary]
    A.need(Path(tool['File']).name == binary and A.read(tool, 128 << 20).startswith(b'\x7fELF'), 'pinned original Linux native tool required')
    argv = [tool['File'], *prefix, *owner_arguments(bundle['Owner'])]
    selected = bundle['Steps'][stage]
    if stage in ['mount', 'facts']:
        pin = selected['SourceSelection']; A.read(pin)
        argv += ['--source-selection-file', pin['File'], '--source-selection-sha256', pin['SHA256']]
    if input_key:
        pin = selected[input_key]; value = A.obj(pin)
        flag = 'mount-layouts' if stage == 'mount' else 'definition'
        argv += ['--'+flag+'-file', pin['File'], '--'+flag+'-sha256', pin['SHA256']]
        if stage == 'mount':
            A.need(value.get('AuthorLonghornHold') is True and value.get('Longhorn'), 'existing Longhorn author opt-in required')
        if stage == 'base-host-materials':
            A.need(value['Version']=='original-observer-host-deployment.v1' and not value.get('LonghornSourceRegistry') and
                   value.get('LonghornVolumes',{'File':'','SHA256':''})=={'File':'','SHA256':''},
                   'base certificate loading must not claim a Longhorn hold or downgrade final materials')
            A.read(value['PKIDefinition']);A.read(value['PKIReceipt'])
        if stage == 'host-materials':
            handoff = A.obj(selected['Handoff'])
            A.need({k:v for k,v in value.items() if k != 'LonghornSourceRegistry'} ==
                   {k:v for k,v in handoff['HostDefinition'].items() if k != 'LonghornSourceRegistry'} and value['LonghornVolumes'] == handoff['LonghornHoldMaterials'] and
                   value.get('LonghornSourceRegistry'), 'same successor plus real signed tenant source registry required')
            check_host_source_core(value,handoff)
    if stage in ['facts', 'host-materials']:
        handoff = A.obj(selected['Handoff'])
        if stage == 'facts':
            A.need(selected['SourceSelection'] == handoff['SourceSelection'], 'facts attempted with old Core/selection')
    if stage != 'facts':
        output = Path(selected['OutputDirectory'])
        A.need(output.is_absolute() and output.resolve(strict=True) == output and output.is_dir(), 'existing final native output directory required')
        argv += ['--output-directory', str(output)]
    return argv


def check_journal_directory(records):
    A.need(os.name == 'posix' and records.is_absolute() and records.resolve(strict=True) == records and
           records.stat().st_mode & 0o077 == 0, 'private Linux journal directory required')


def run_stage(bundle_pin, stage, records, execute=False, run=subprocess.run):
    bundle = A.obj(bundle_pin)
    argv = stage_argv(bundle, stage)
    if not execute:
        return {'Version':'p2-native-command-review.v1', 'Stage':stage, 'Argv':argv, 'Executed':False, 'BackupReady':False}
    check_journal_directory(records)
    sent, completed = records / (stage+'.sent.private.json'), records / (stage+'.completed.private.json')
    binary=STAGES[stage][0]
    binding = {'Stage':stage, 'Argv':argv, 'Owner':bundle['Owner'], 'Tool':bundle['Tools'][binary], 'Inputs':bundle['Steps'][stage]}
    if sent.exists():
        A.need(A.decode(sent.read_bytes()) == binding, 'original stage binding changed')
        A.need(completed.exists(), 'native send outcome unknown: retain outputs; reconcile original owner, never resend')
        result = A.decode(completed.read_bytes())
        A.read(result['Stdout']); A.read(result['Stderr'])
        A.need(result['ExitCode'] == 0, 'native owner refused; retain original records')
        return result
    A.need(not completed.exists(), 'orphan native completion record')
    A.retain(sent, binding)
    # Persist intent before launch. Timeout/EOF/parse failure never authorizes
    # another send. Native stdout remains exact (including its final newline).
    p = run(argv, capture_output=True, timeout=180)
    stdout = A.retain(records / (stage+'.stdout.private'), p.stdout or b'\n')
    stderr = A.retain(records / (stage+'.stderr.private'), p.stderr or b'\n')
    result = {'Stage':stage, 'ExitCode':p.returncode, 'Stdout':stdout, 'Stderr':stderr, 'BackupReady':False}
    A.retain(completed, result)
    A.need(p.returncode == 0, 'native owner refused; retain private logs and recovery obligations')
    return result


def check_node_tls(receipt, now, connect=socket.create_connection):
    before, after = (datetime.datetime.fromisoformat(receipt[k].replace('Z','+00:00')) for k in ['NotBefore','NotAfter'])
    A.need(before <= now < after, 'expired observer must be renewed and installed')
    for key in ['CA','ClientCertificate','ClientKey']: A.read(receipt[key])
    ctx = ssl.create_default_context(cafile=receipt['CA']['File'])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(receipt['ClientCertificate']['File'], receipt['ClientKey']['File'])
    checks = []
    for endpoint in receipt['Endpoints']:
        expected = endpoint['Endpoint']; url = urlsplit(expected['URL'])
        A.need(url.scheme == 'https' and url.hostname and url.port and expected['ServerURI'].startswith('spiffe://'), 'original Node TLS endpoint required')
        with connect((url.hostname, url.port), timeout=10) as tcp:
            with ctx.wrap_socket(tcp, server_hostname=url.hostname) as tls:
                uris = [v for kind,v in tls.getpeercert().get('subjectAltName',[]) if kind == 'URI']
                A.need(uris == [expected['ServerURI']] and tls.version() == 'TLSv1.3', 'actual Node mTLS identity changed')
        checks.append({'Node':endpoint['Node'], 'Kind':endpoint['Kind'], 'ServerURI':expected['ServerURI']})
    A.need(checks, 'complete endpoint census required')
    return {'Version':'p2-node-mtls-readback.v1', 'Checks':checks, 'NativeFDOrHoldVerified':False, 'BackupReady':False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle-file'); p.add_argument('--bundle-sha256')
    p.add_argument('--stage', choices=sorted(STAGES))
    p.add_argument('--records-directory', type=Path, required=True)
    p.add_argument('--execute-native', action='store_true')
    p.add_argument('--check-node-tls',action='store_true')
    p.add_argument('--observer-receipt-file'); p.add_argument('--observer-receipt-sha256')
    args = p.parse_args(); os.umask(0o077)
    if args.check_node_tls:
        check_journal_directory(args.records_directory)
        A.need(not args.execute_native and not args.stage and args.observer_receipt_file and args.observer_receipt_sha256,'only explicit read-only Node TLS check required')
        receipt=A.obj({'File':args.observer_receipt_file,'SHA256':args.observer_receipt_sha256})
        result=check_node_tls(receipt,datetime.datetime.now(datetime.timezone.utc))
        A.retain(args.records_directory/'node-mtls-readback.json',result)
    else:
        A.need(args.bundle_file and args.bundle_sha256 and args.stage,'native stage input pin required')
        result = run_stage({'File':args.bundle_file, 'SHA256':args.bundle_sha256}, args.stage, args.records_directory, args.execute_native)
    # Actual native bytes/credentials remain private; this result contains only
    # file pins or review argv (paths, never secret file contents).
    print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        raise SystemExit('P2_NATIVE_CANDIDATE_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))
