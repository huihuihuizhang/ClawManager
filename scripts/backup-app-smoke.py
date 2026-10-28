"""Smoke an explicit local final App image; never contacts the shared server.

Uses the task-owned disposable MySQL, an isolated schema and Redis/container.
Credentials stay in process memory or a removed private local env file. This
checks actual Nginx/API/auth/disabled-capability behavior, not browser rendering
or complete backup publication/restore.
"""
import argparse
import json
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent.parent


def run(args, body=None):
    r = subprocess.run(args, input=body, capture_output=True, timeout=60, cwd=ROOT)
    if r.returncode:
        raise RuntimeError('local smoke fixture command failed')
    return r.stdout.decode().strip()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mysql', required=True)
    p.add_argument('--image', required=True)
    a = p.parse_args()
    if not re.fullmatch(r'cm-backup-[a-z0-9-]+', a.mysql) or not re.fullmatch(r'cm-backup-app:[a-z0-9.-]+', a.image):
        raise RuntimeError('explicit task-owned local fixtures required')
    db = json.loads(run(['docker', 'inspect', a.mysql]))[0]
    if db['Config']['Labels'].get('codex.task') != 'backup-team-integration':
        raise RuntimeError('MySQL ownership mismatch')
    host = db['NetworkSettings']['Networks']['kind']['IPAddress']
    if not host:
        raise RuntimeError('task MySQL has no local kind network')
    image = json.loads(run(['docker', 'image', 'inspect', a.image]))[0]['Id']
    suffix = uuid.uuid4().hex
    schema, user = 'cm_app_' + suffix, 'app_' + suffix[:16]
    password = secrets.token_hex(32)
    redis, app = 'cm-backup-app-redis-' + suffix[:10], 'cm-backup-app-smoke-' + suffix[:10]
    created = []
    env_path = None
    def sql(text):
        return run(['docker', 'exec', '-i', a.mysql, 'mysql', '-N', '-B', '-uroot'], text.encode())
    def request(path, method='GET', data=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        r = urllib.request.Request(base + path, method=method, headers=headers,
                                   data=None if data is None else json.dumps(data).encode())
        try:
            response = urllib.request.urlopen(r, context=ssl._create_unverified_context(), timeout=10)
        except urllib.error.HTTPError as e:
            response = e
        with response:
            return response.status, response.headers, response.read(4 << 20)
    try:
        sql(f"CREATE DATABASE `{schema}`; CREATE USER '{user}'@'%' IDENTIFIED BY '{password}'; GRANT ALL PRIVILEGES ON `{schema}`.* TO '{user}'@'%';")
        redis_id = run(['docker', 'run', '-d', '--name', redis, '--label', 'codex.task=backup-team-integration', '--network', 'kind', 'redis:7-alpine'])
        created.append((redis, redis_id))
        private = ROOT / 'reports' / 'm3m4-app-smoke'
        private.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n', dir=private, delete=False) as env:
            env_path = Path(env.name)
            env.write('\n'.join([
                'DB_HOST=' + host, 'DB_PORT=3306', 'DB_USER=' + user, 'DB_PASSWORD=' + password,
                'DB_NAME=' + schema, 'JWT_SECRET=' + secrets.token_hex(48),
                'PLATFORM_REDIS_URL=redis://' + redis + ':6379/0', 'CLAWMANAGER_LEADER_ELECTION=false',
                'SYSTEM_BACKUP_READ_LIVE_ENABLED=true', 'SYSTEM_BACKUP_CONTROLLER_ENABLED=false',
                'SYSTEM_BACKUP_V2_EXECUTION_ENABLED=false', 'SYSTEM_BACKUP_ENABLED=false',
                'SYSTEM_BACKUP_INSTALLATION_ID=installation_app_smoke',
            ]) + '\n')
        app_id = run(['docker', 'run', '-d', '--name', app, '--label', 'codex.task=backup-team-integration',
                      '--network', 'kind', '--env-file', str(env_path), '-p', '127.0.0.1::8443', a.image])
        created.append((app, app_id))
        env_path.unlink()
        env_path = None
        actual = json.loads(run(['docker', 'inspect', app]))[0]
        port = actual['NetworkSettings']['Ports']['8443/tcp'][0]['HostPort']
        base = 'https://127.0.0.1:' + port
        until = time.monotonic() + 75
        while True:
            try:
                status, _, body = request('/api/v1/version')
                if status == 200:
                    break
            except (OSError, urllib.error.URLError):
                pass
            if time.monotonic() >= until:
                raise RuntimeError('actual App API did not become ready')
            time.sleep(0.5)
        version = json.loads(body)
        status, headers, html = request('/')
        if status != 200 or b'<!doctype html>' not in html.lower() or 'no-store' not in headers.get('Cache-Control', ''):
            raise RuntimeError('actual SPA/cache response invalid')
        assets = re.findall(rb'<script[^>]+src="(/assets/[^\"]+\.js)"', html)
        if not assets:
            raise RuntimeError('final App has no built frontend entry')
        for asset in assets:
            status, headers, _ = request(asset.decode())
            if status != 200 or 'javascript' not in headers.get('Content-Type', ''):
                raise RuntimeError('built JavaScript entry unavailable')
        for path in ['/api/v1/teams', '/api/v1/instances', '/api/v1/admin/system-backups']:
            if request(path)[0] != 401:
                raise RuntimeError('unauthenticated API did not reject access')
        status, _, raw = request('/api/v1/auth/login', 'POST', {'username': 'admin', 'password': 'admin123'})
        if status != 200:
            raise RuntimeError('actual seeded login failed')
        token = json.loads(raw)['data']['access_token']
        for path in ['/api/v1/teams', '/api/v1/instances']:
            if request(path, token=token)[0] != 200:
                raise RuntimeError('existing Team/instance list regressed')
        for method, path, data in [('GET', '/api/v1/admin/system-backups', None),
                                   ('POST', '/api/v1/admin/system-backups', {'requested_parts': ['workspace'], 'task_purpose': 'functional_test'})]:
            if request(path, method, data, token)[0] != 503:
                raise RuntimeError('missing backup pins/capability were not rejected')
        if request('/api/v1/admin/system-backup/tasks', token=token)[0] != 503:
            raise RuntimeError('legacy backup access did not retain its own permission gate')
        count = sql(f'SELECT COUNT(*) FROM `{schema}`.system_backup_v2_backups; SELECT COUNT(*) FROM `{schema}`.system_backup_tasks;')
        if count.splitlines() != ['0', '0']:
            raise RuntimeError('disabled backup submission left persistent tasks')
        print(json.dumps({'result': 'passed', 'image_id': image, 'version_response': version,
                          'checks': ['actual HTTPS Nginx/API', 'fresh migrations', 'SPA no-store and built JS',
                                     'real login', 'Team/instance lists', 'anonymous rejection',
                                     'missing live authority rejects reads/create', 'legacy gate retained',
                                     'zero accidental backup tasks'],
                          'boundary': 'isolated empty-business fixture; not browser, full backup or restore acceptance'}))
    finally:
        if env_path:
            env_path.unlink(missing_ok=True)
        for name, expected in reversed(created):
            obj = json.loads(run(['docker', 'inspect', name]))[0]
            if obj['Id'] != expected or obj['Config']['Labels'].get('codex.task') != 'backup-team-integration':
                raise RuntimeError('cleanup ownership changed')
            run(['docker', 'rm', '-f', expected])
        sql(f"DROP DATABASE IF EXISTS `{schema}`; DROP USER IF EXISTS '{user}'@'%';")


if __name__ == '__main__':
    main()
