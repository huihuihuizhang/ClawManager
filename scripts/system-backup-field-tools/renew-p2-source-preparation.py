#!/usr/bin/env python3
"""Renew this original source reader and reauthor preparation DATA, no task grant."""
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
API = Path('/root/sbk/p2-api-runtime-inputs.WWN62yPS/source-api-fragment.json')
API_SHA = '83fa7d8304c986e767387f53a4bcee1ee412dfef50e4305cba7faf54418a2142'
BIN = Path('/root/sbk/p2-jwt-api-c888315f/system-backup-first-install-materials')
BIN_SHA = '55c279a67b84c88c21eef9615cc29d31ac7457e58ac4c997f19b72a4b0357de9'
NS = 'clawmanager-sbk-validation-system'
KUBE = '/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml'

def need(ok, why):
    if not ok:
        raise ValueError(why)

def moment(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))

def preparation_window(now, token_until, observer_until, agent_until):
    until = min(now + dt.timedelta(hours=8), token_until, observer_until, agent_until)
    need(until > now + dt.timedelta(minutes=5), 'renewed credentials/certificates leave less than five minutes')
    return now - dt.timedelta(seconds=5), until

def successor_definition(original, old_connection, new_connection, old_out, new_out, before, until):
    need(original['Version'] == 'original-initial-source-author-inputs.v1', 'original author definition required')
    value = copy.deepcopy(original)
    matches = [i for i,c in enumerate(value['Connections']) if c['Purpose'] == 'source_api']
    need(len(matches) == 1 and value['Connections'][matches[0]] == old_connection, 'original source API binding changed')
    need({k:v for k,v in old_connection.items() if k != 'Credential'} ==
         {k:v for k,v in new_connection.items() if k != 'Credential'} and
         old_connection['Credential']['File'] != new_connection['Credential']['File'], 'only a new credential for the same source identity is allowed')
    discovery = value['Materials']['Discovery']
    need(discovery['SourceAPI']['token_file'] == old_connection['Credential']['File'] and
         discovery['SourceAPITokenSHA256'] == old_connection['Credential']['SHA256'], 'original capture API pin changed')
    need(value['Materials']['DeploymentConfigSHA256'] == '' and value['Materials']['CaptureGrantSHA256'] == '', 'unissued initial template required')
    core = value['Deployment']
    need(core['profile_file'] == str(old_out/'execution-profile.json') and
         core['capture_modules']['path'] == str(old_out/'capture-materials.json'), 'exact original output paths required')
    core['profile_file'] = str(new_out/'execution-profile.json')
    core['capture_modules']['path'] = str(new_out/'capture-materials.json')
    value['Connections'][matches[0]] = copy.deepcopy(new_connection)
    discovery['SourceAPI']['token_file'] = new_connection['Credential']['File']
    discovery['SourceAPITokenSHA256'] = new_connection['Credential']['SHA256']
    value['NotBefore'], value['Until'] = (x.isoformat().replace('+00:00','Z') for x in (before,until))
    return value

def main():
    os.umask(0o077)
    need(os.name == 'posix', 'Linux operator required')
    spec = importlib.util.spec_from_file_location('renew_assembly', Path(__file__).with_name('assemble-p2-installation-candidate.py'))
    A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
    r = ROOT/'source-preparation-renew8h'
    r.mkdir(mode=0o700, exist_ok=True)
    need(r.resolve(strict=True) == r and r.stat().st_mode & 0o077 == 0, 'private original records directory required')
    save = A.retain
    def call(args, body=None, config=KUBE):
        p = subprocess.run(['kubectl','--kubeconfig',config,'--request-timeout=20s',*args],
            input=None if body is None else json.dumps(body).encode(), capture_output=True, timeout=40)
        need(p.returncode == 0, 'source API operation refused; credentials not printed')
        return json.loads(p.stdout)
    def identity(status, account, uid):
        user = status.get('userInfo',status.get('user',{}))
        need(status.get('authenticated',True) is True and not status.get('error') and
             user.get('username') == 'system:serviceaccount:'+NS+':'+account and user.get('uid') == uid,
             'authenticated source account mismatch')
    previous = json.loads((ROOT/'initial-source-author/completed.json').read_bytes())
    receipt = A.obj(previous['Receipt'])
    need(receipt['SourceSelection']['SHA256'] == '2bc613fa44cb80632f75a5189c8242a935c57cfea6e6ea46b5688e650a889577', 'exact expired source selection required')
    selected = A.obj(receipt['SourceSelection'])
    original = A.obj(previous['Definition'])
    for key in ['PartsFile','SourceWritersFile','RedisSourcesFile']:
        need(not selected.get(key) or not Path(selected[key]).exists(), 'source facts already exist; reconcile before reauthoring')
    api = A.obj({'File':str(API),'SHA256':API_SHA})
    A.read({'File':str(BIN),'SHA256':BIN_SHA},128<<20)
    vault = json.loads((ROOT/'vault-dependency/completed.json').read_bytes())
    for key in ['Receipt','WriterSelection','InstalledObserver']: A.read(vault[key])
    if (r/'completed.json').exists():
        done = json.loads((r/'completed.json').read_bytes()); A.read(done['Receipt'])
        print('P2_SOURCE_PREPARATION_ALREADY_REAUTHORED',json.dumps(done)); return
    need(not (r/'author.sent.private.json').exists(), 'native author already sent; retain and inspect original outcome')
    account, uid = api['service_account'], api['service_account_uid']
    def check_account():
        sa = call(['-n',NS,'get','serviceaccount',account,'-o','json'])
        need(sa['metadata']['uid'] == uid == api['connection']['Account'] and not sa['metadata'].get('deletionTimestamp'), 'original source account replaced')
    check_account()
    token_receipt = r/'token.receipt.private.json'
    if token_receipt.exists():
        response = json.loads(token_receipt.read_bytes())
    else:
        need(not (r/'token.sent.private.json').exists(), 'token issuance outcome unknown; do not reissue')
        body = {'apiVersion':'authentication.k8s.io/v1','kind':'TokenRequest','spec':{'expirationSeconds':28800}}
        save(r/'token.sent.private.json',{'Account':account,'UID':uid,'Request':body})
        response = call(['create','--raw','/api/v1/namespaces/'+NS+'/serviceaccounts/'+account+'/token','-f','-'],body)
        save(token_receipt,response)
    token = response['status']['token']
    token_until = moment(response['status']['expirationTimestamp'])
    before, until = preparation_window(dt.datetime.now(dt.timezone.utc),token_until,
        moment(json.loads((ROOT/'observer.receipt.private.json').read_bytes())['NotAfter']),
        moment(json.loads((ROOT/'runtime-agent.receipt.private.json').read_bytes())['NotAfter']))
    review = call(['create','--raw','/apis/authentication.k8s.io/v1/tokenreviews','-f','-'],
        {'apiVersion':'authentication.k8s.io/v1','kind':'TokenReview','spec':{'token':token}})
    identity(review['status'],account,uid)
    connection = copy.deepcopy(api['connection'])
    connection['Credential'] = save(r/'source-api.jwt',token.encode('ascii'))
    A.read(connection['CA'])
    config = {'apiVersion':'v1','kind':'Config','clusters':[{'name':'source','cluster':{
        'server':connection['Endpoint'],'certificate-authority':connection['CA']['File']}}],
        'users':[{'name':'source','user':{'tokenFile':connection['Credential']['File']}}],
        'contexts':[{'name':'source','context':{'cluster':'source','user':'source','namespace':NS}}],'current-context':'source'}
    config_pin = save(r/'source.kubeconfig.private.json',config)
    config_file = config_pin['File']
    review = call(['create','--raw','/apis/authentication.k8s.io/v1/selfsubjectreviews','-f','-'],
        {'apiVersion':'authentication.k8s.io/v1','kind':'SelfSubjectReview'},config_file)
    identity(review['status'],account,uid)
    for ns in [NS,'clawmanager-sbk-validation-user-1']:
        for group, resource in [('apis/apps/v1','deployments'),('api/v1','pods'),('api/v1','persistentvolumeclaims')]:
            call(['get','--raw','/'+group+'/namespaces/'+ns+'/'+resource],config=config_file)
    call(['-n','longhorn-system','get','volumes.longhorn.io','-o','json'],config=config_file)
    check_account()
    refreshed = copy.deepcopy(api); refreshed['connection'] = connection; refreshed['token_expires_unix'] = int(token_until.timestamp())
    api_pin = save(r/'source-api-fragment.json',refreshed)
    old_out = Path(receipt['SourceSelection']['File']).parent
    out = old_out.parent/'initial-source-renew8h'
    out.mkdir(mode=0o700,exist_ok=True)
    need(out.resolve(strict=True) == out and out.stat().st_mode & 0o077 == 0 and not list(out.iterdir()), 'new empty native output directory required')
    definition = successor_definition(original,api['connection'],connection,old_out,out,before,until)
    definition_pin = save(r/'definition.private.json',definition)
    old_argv = json.loads((ROOT/'observer.sent.private.json').read_bytes())['Argv']
    common = old_argv[1:old_argv.index('--definition-file')]
    argv = [str(BIN),'author-initial-source-inputs',*common,'--definition-file',definition_pin['File'],
        '--definition-sha256',definition_pin['SHA256'],'--output-directory',str(out)]
    save(r/'author.sent.private.json',{'Argv':argv,'ParentReceipt':previous['Receipt'],'Definition':definition_pin,
        'SourceAPI':api_pin,'VaultWriterSelection':vault['WriterSelection'],'NotBefore':definition['NotBefore'],'Until':definition['Until']})
    with (r/'author.stdout.private').open('xb') as stdout, (r/'author.stderr.private').open('xb') as stderr:
        result = subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=180)
    save(r/'author.exit.json',{'ExitCode':result.returncode})
    need(result.returncode == 0, 'native source author refused; retain new records and partial outputs')
    raw = (r/'author.stdout.private').read_bytes(); value = json.loads(raw)
    need(value['Version'] == 'original-initial-source-inputs-authored.v1' and
         value['GrantsIssued'] is False and value['BackupReady'] is False, 'actual unissued source DATA receipt required')
    for key in ['Deployment','MaterialsTemplate','ExecutionProfile','SourceSelection']: A.read(value[key])
    done = {'Version':'p2-source-preparation-reauthored.v1','Receipt':save(r/'author.receipt.private.json',raw),
        'SourceSelection':value['SourceSelection'],'SourceAPI':api_pin,'VaultWriterSelection':vault['WriterSelection'],
        'NotBefore':definition['NotBefore'],'Until':definition['Until'],'TokenNotAfter':token_until.isoformat(),
        'GrantsIssued':False,'BackupReady':False}
    save(r/'completed.json',done)
    print('P2_SOURCE_PREPARATION_REAUTHORED_NO_HOLD',json.dumps(done),flush=True)

if __name__ == '__main__':
    try: main()
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as error:
        raise SystemExit('P2_SOURCE_RENEWAL_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))
