#!/usr/bin/env python3
"""Renew the recovered source identity, then author tenant team Longhorn material."""
import base64
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
PARENT = ROOT / 'source-preparation-20261113-runtime-recovered'
RECEIPT_SHA = 'a57883aa0ff3403cdd529120b9f7ec7146f755fc3cc6cb183a449e051a38749d'
SELECTION_SHA = '99e192900ec2428c38554cfdc5348329d108b7dc8ff0a8935b240f34e3a24b1e'
DEFINITION_SHA = '4712e78a8d40eb73d2c3cc6ae553e61648695379abe8237a453692775979870f'


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def identity(A, status, account, uid):
    user = status.get('userInfo', status.get('user', {}))
    A.need(status.get('authenticated', True) is True and not status.get('error') and
           user.get('username') == 'system:serviceaccount:' + A.NS + ':' + account and user.get('uid') == uid,
           'renewed source identity differs')


def window(now, token_until, observer_until, agent_until):
    # Existing Vault metadata credential is independently checked below. Never
    # extend its lifetime or reuse the expired Kubernetes credential.
    until = min(now + dt.timedelta(hours=2), token_until, observer_until, agent_until)
    if until < now + dt.timedelta(minutes=20):
        raise ValueError('credentials leave less than twenty minutes; renew certificates first')
    return now - dt.timedelta(seconds=5), until


def prepare(A, L):
    H, R, N, D, F = [load(n) for n in ('prepare-p2-longhorn-provider-loaded', 'resume-p2-recovered-source',
        'renew-p2-source-preparation', 'p2-source-dns', 'p2-vault-local-forward')]
    parent = A.decode((PARENT / 'completed.json').read_bytes())
    A.need(parent['Receipt']['SHA256'] == RECEIPT_SHA and parent['Definition']['SHA256'] == DEFINITION_SHA and
           parent['SourceSelection']['SHA256'] == SELECTION_SHA and parent['GrantsIssued'] is False and
           parent['BackupReady'] is False, 'observed recovered source required')
    receipt, selected, original = (A.obj(parent[k]) for k in ('Receipt', 'SourceSelection', 'Definition'))
    A.need(receipt['SourceSelection'] == parent['SourceSelection'] and selected['Controller'] == parent['Controller'] and
           original['Controller'] == selected['Controller'], 'recovered source chain differs')
    for key in ('PartsFile', 'SourceWritersFile', 'RedisSourcesFile'):
        A.need(not selected.get(key) or not Path(selected[key]).exists(), 'source facts already authored')
    prior = ROOT / 'longhorn-source-20261113-runtime-recovered-census-window'
    args = A.decode((prior / 'native.sent.private.json').read_bytes())['Argv']
    failure = A.decode((prior / 'native.stdout.private').read_bytes())
    failed_out = Path(args[args.index('--output-directory') + 1])
    A.need(A.decode((prior / 'native.exit.json').read_bytes()) == {'ExitCode': 1} and
           failure.get('Status') == 'original_mount_author_refused' and failure.get('Phase') == 'longhorn_sources' and
           args[args.index('--source-selection-sha256') + 1] == SELECTION_SHA and
           failed_out == Path(parent['SourceSelection']['File']).parent.parent / prior.name and
           failed_out.resolve(strict=True) == failed_out and not list(failed_out.iterdir()) and
           not (prior / 'completed.json').exists(), 'observed refusal without source outputs required')
    journal = ROOT / 'source-preparation-20261113-tenant-team-renewed'
    journal.mkdir(mode=0o700, exist_ok=True)
    A.need(journal.resolve() == journal and journal.stat().st_mode & 0o077 == 0, 'private renewal journal required')
    print('P2_TENANT_TEAM_RENEWAL_RECORDS', journal, flush=True)
    if (journal / 'completed.json').exists():
        done = A.decode((journal / 'completed.json').read_bytes())
        A.read(done['Receipt']); A.read(done['Definition']); A.read(done['SourceSelection'])
        return done, journal / 'author.sent.private.json'
    A.need(not (journal / 'author.sent.private.json').exists(), 'native renewal already attempted; retain partial outputs')
    site = L.Site(journal, A)
    app = R.verify_app(A, site)
    desired = A.obj(A.decode((H.PARENT / 'delivery-plan.private.json').read_bytes())['DesiredSpec'])
    pod = H.current_controller(site, A, L, selected, desired)
    observer = A.obj({'File': str(ROOT / 'renewal-20261113/observer/receipt.private.json'),
        'SHA256': 'c0d69a9d9d1254a40993fb5516ed936325f265a74b0dde4b3823ea52fdd010f5'})
    agent = A.obj({'File': str(ROOT / 'renewal-20261113/runtime-unique/runtime-agent.receipt.private.json'),
        'SHA256': '1d61b1d11b3427fd46d9d2eab3bd04f19daf74ae3a674a9f2275269c1810f149'})
    now = dt.datetime.now(dt.timezone.utc)
    _, tentative_until = window(now, now + dt.timedelta(hours=8), N.moment(observer['NotAfter']), N.moment(agent['NotAfter']))
    formal = A.obj({'File': str(L.PARENT / 'receipt.private.json'), 'SHA256': L.RECEIPT_SHA})
    secret = A.obj(formal['SecretManifest']); L.verify_secret(site.get('secret', secret['metadata']['name']), secret)
    provider, token = [base64.b64decode(secret['data'][k], validate=True) for k in ('observer.json', 'token')]
    L.verify_metadata(A, F, site, journal, A.decode(provider), token, formal['Workload'], tentative_until)
    api = A.obj(parent['SourceAPI'])
    connection = api['connection']
    A.need(next(c for c in selected['Connections'] if c['Purpose'] == 'source_api') == connection,
           'parent source API fragment differs')
    account, uid = api['service_account'], api['service_account_uid']
    sa = site.get('serviceaccount', account)
    A.need(sa['metadata']['uid'] == uid == connection['Account'] and not sa['metadata'].get('deletionTimestamp'),
           'source account replaced')
    if (journal / 'token.receipt.private.json').exists():
        response = A.decode((journal / 'token.receipt.private.json').read_bytes())
    else:
        body = {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenRequest', 'spec': {'expirationSeconds': 28800}}
        raw = site.send('token', ['create', '--raw', '/api/v1/namespaces/' + A.NS + '/serviceaccounts/' + account + '/token', '-f', '-'], json.dumps(body).encode())
        response = A.decode(raw); A.retain(journal / 'token.receipt.private.json', raw)
    token = response['status']['token']
    review = A.decode(site.call(['create', '--raw', '/apis/authentication.k8s.io/v1/tokenreviews', '-f', '-'],
        json.dumps({'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenReview', 'spec': {'token': token}}).encode()))
    identity(A, review['status'], account, uid)
    before, until = window(now, N.moment(response['status']['expirationTimestamp']), N.moment(observer['NotAfter']), N.moment(agent['NotAfter']))
    new_connection = copy.deepcopy(connection)
    new_connection['Credential'] = A.retain(journal / 'source-api.jwt', token.encode('ascii'))
    refreshed = copy.deepcopy(api); refreshed['connection'] = new_connection
    refreshed['token_expires_unix'] = int(N.moment(response['status']['expirationTimestamp']).timestamp())
    api_pin = A.retain(journal / 'source-api-fragment.json', refreshed)
    old_out = Path(parent['SourceSelection']['File']).parent
    out = old_out.parent / 'initial-source-20261113-tenant-team-renewed'
    definition = N.successor_definition(original, connection, new_connection, old_out, out, before, until)
    definition_pin = A.retain(journal / 'definition.private.json', definition)
    A.need(not out.exists(), 'new native source output directory required'); out.mkdir(mode=0o700)
    old = A.decode((PARENT / 'author.sent.private.json').read_bytes())['Argv']
    A.need(old[:2] == [str(L.BIN), 'author-initial-source-inputs'] and old[old.index('--definition-sha256') + 1] == DEFINITION_SHA,
           'original source author invocation differs')
    A.read({'File': str(L.BIN), 'SHA256': L.BIN_SHA}, 128 << 20)
    from urllib.parse import urlsplit
    endpoints = [(c['Purpose'], c['Endpoint']) for c in selected['Connections']
                 if (urlsplit(c['Endpoint']).hostname or '').endswith('.' + A.NS + '.svc')]
    dns = D.SourceDNS(site, journal, pod, endpoints, A.retain); dns.probe()
    result = R.once(A, dns, journal, 'author', [str(L.BIN), 'author-initial-source-inputs', *old[2:old.index('--definition-file')],
        '--definition-file', definition_pin['File'], '--definition-sha256', definition_pin['SHA256'], '--output-directory', str(out)])
    A.need(result['Version'] == 'original-initial-source-inputs-authored.v1' and result['GrantsIssued'] is False and result['BackupReady'] is False,
           'unsigned native source receipt required')
    for key in ('Deployment', 'MaterialsTemplate', 'ExecutionProfile', 'SourceSelection'): A.read(result[key])
    actual = A.obj(result['SourceSelection'])
    A.need(actual['Connections'] == definition['Connections'] and actual['Controller'] == selected['Controller'] and
           actual['Until'] == definition['Until'] and A.obj(result['Deployment']) == definition['Deployment'], 'native source successor differs')
    A.need(R.verify_app(A, site)['spec'] == app['spec'], 'application drift during renewal')
    H.current_controller(site, A, L, selected, desired)
    done = {'Version': 'p2-tenant-team-source-renewed.v1', 'Receipt': A.retain(journal / 'receipt.private.json', (journal / 'author.receipt.private.json').read_bytes()),
        'Definition': definition_pin, 'SourceSelection': result['SourceSelection'], 'SourceAPI': api_pin,
        'VaultWriterSelection': parent['VaultWriterSelection'], 'Until': definition['Until'], 'TokenReissued': True,
        'GrantsIssued': False, 'BackupReady': False}
    A.retain(journal / 'completed.json', done)
    print('P2_TENANT_TEAM_SOURCE_RENEWED_NO_HOLD', json.dumps(done), flush=True)
    return done, journal / 'author.sent.private.json'


if __name__ == '__main__':
    try:
        os.umask(0o077)
        load('prepare-p2-longhorn-provider-loaded').main(tenant_team=True)
    except Exception as error:
        raise SystemExit('P2_TENANT_TEAM_SOURCE_UNCONFIRMED ' + (str(error) if type(error) is ValueError else type(error).__name__))
