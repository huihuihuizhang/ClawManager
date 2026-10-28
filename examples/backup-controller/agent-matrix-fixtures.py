"""Native image exercises on fixed disposable paths, without model credentials.

No vendor schema is guessed: Hermes uses its bundled SessionDB API, OpenCode
uses its local HTTP API, other engines initialize their own state. Additional
history/task/credential fixtures are explicitly synthetic, not native records.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

HOME = Path('/home-lab')
LAB = Path('/lab')
CASE = json.loads((LAB / 'case.json').read_text(encoding='utf-8-sig'))
UID = CASE['UID']
NAME = CASE['Name']
TYPE = CASE['Type']
MODE = CASE['Mode']
ENV = dict(os.environ, HOME=str(HOME), XDG_CONFIG_HOME=str(HOME / '.config'),
           XDG_DATA_HOME=str(HOME / '.local/share'), XDG_CACHE_HOME=str(HOME / '.cache'),
           HERMES_HOME=str(HOME / '.hermes'), DSH_HOME=str(HOME / '.dsh'),
           OPENCODE_CONFIG_DIR=str(HOME / '.opencode'),
           CLAWMANAGER_WORKSPACE_PATH=str(HOME / 'workspace'),
           OPENCODE_DISABLE_MODELS_FETCH='true', DSH_TELEMETRY_DISABLED='1',
           OPENCLAW_STATE_DIR=str(HOME / '.openclaw'), OPENCLAW_CONFIG_PATH=str(HOME / '.openclaw/openclaw.json'))


def run(args, timeout=60, env=None):
    r = subprocess.run(args, env=env or ENV, cwd=HOME / 'workspace',
                       user=UID, group=UID, extra_groups=[], capture_output=True, timeout=timeout)
    with (LAB / 'native.log').open('ab') as f:
        f.write(r.stdout + r.stderr)
    if r.returncode:
        raise RuntimeError('native command failed: ' + args[0] + ' exit=' + str(r.returncode))
    return r.stdout.decode(errors='replace')


def start(args, env=None):
    log = (LAB / 'native.log').open('ab')
    try:
        return subprocess.Popen(args, env=env or ENV, cwd=HOME / 'workspace', user=UID,
                                group=UID, extra_groups=[], stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
    finally:
        log.close()


def stop(p):
    if p.poll() is None:
        p.terminate()
    try:
        p.wait(timeout=25)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait(timeout=5)
        raise RuntimeError('native process required forced stop; not a consistent capture')
    # A supervisor can leave children after its own orderly exit. Signal only
    # the synthetic process group we created, then prepare() checks /proc.
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass


def http(port, path='/', data=None):
    body = None if data is None else json.dumps(data).encode()
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=body,
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=3) as r:
        return r.read()


def wait_ready(p, probe, seconds=70):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if p.poll() is not None:
            raise RuntimeError('native service exited before readiness')
        try:
            return probe()
        except (OSError, ValueError, RuntimeError):
            time.sleep(1)
    raise RuntimeError('native readiness timeout')


def wb_health():
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(3)
        s.connect('/tmp/workbuddy.sock')
        s.sendall(b'GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n')
        data = b''
        while True:
            b = s.recv(4096)
            if not b:
                break
            data += b
    obj = json.loads(data.split(b'\r\n\r\n', 1)[1])
    if not obj.get('daemonReady') or obj.get('daemonExited'):
        raise RuntimeError('daemon not ready')
    return obj


def hermes_python():
    base = '/opt/hermes-agent' if MODE == 'lite' else '/usr/local/lib/hermes-agent'
    py = base + ('/.venv/bin/python' if MODE == 'lite' else '/venv/bin/python')
    return base, py


def native_prepare():
    out = {'case': NAME, 'native_session_api_verified': False, 'gateway_health_verified': False}
    if TYPE == 'hermes':
        out['version'] = run(['hermes', '--version']).strip()
        run(['hermes', 'config', 'set', 'model', 'synthetic-lab-model'])
        base, py = hermes_python()
        run([py, '-c', "import sys;sys.path.insert(0,sys.argv[1]);from hermes_state import SessionDB;db=SessionDB();db.create_session('backup-lab-session','cli');db.append_message('backup-lab-session','user','synthetic persistent message');db.close()", base])
        out['native_session_api_verified'] = True
        command = ['hermes', 'serve' if MODE == 'lite' else 'dashboard', '--host', '127.0.0.1', '--port', '9119', '--skip-build']
        if MODE == 'lite':
            command.append('--isolated')
        else:
            command.append('--no-open')
        env = dict(ENV, CLAWMANAGER_CONTROL_UI_ORIGIN='http://127.0.0.1:9119', CLAWMANAGER_TRUSTED_PROXY_CIDRS='127.0.0.1/32') if MODE == 'lite' else ENV
        p = start(command, env)
        try:
            wait_ready(p, lambda: http(9119))
            out['gateway_health_verified'] = True
        finally:
            stop(p)
    elif TYPE == 'opencode':
        out['version'] = run(['opencode', '--version']).strip()
        env = dict(ENV, HOST='127.0.0.1', PORT='4096', CLAWMANAGER_GATEWAY_PORT='4096')
        p = start(['/usr/local/bin/start-opencode-pro-web' if MODE == 'pro' else '/usr/local/bin/start-opencode-web'], env)
        try:
            wait_ready(p, lambda: http(4096, '/global/health'))
            session = json.loads(http(4096, '/session', {'title': 'Synthetic backup lab ' + NAME}))
            out['native_session_id'] = session['id']
            out['native_session_api_verified'] = True
            out['gateway_health_verified'] = True
        finally:
            stop(p)
    elif TYPE == 'deepseek-harness':
        out['version'] = run(['dsh', '--version']).strip()
        env = dict(ENV, CLAWMANAGER_GATEWAY_PORT='3080', DSH_BIND_HOST='127.0.0.1',
                   CLAWMANAGER_LLM_BASE_URL='http://127.0.0.1:9/v1', CLAWMANAGER_LLM_API_KEY='synthetic-not-a-real-key',
                   CLAWMANAGER_LLM_MODEL='["synthetic-lab-model"]', OPENAI_MODEL='synthetic-lab-model')
        # Pro wrapper uses /config/workspace unconditionally. The runner mounts
        # this fresh instance home at /config too; it never uses a host path.
        if MODE == 'pro':
            run(['/usr/local/bin/prepare-deepseek-harness-resources'], env=env)
        # Both cached rc.6 images need this Node CLI flag for their bundled
        # Cordis HMR service. Node explicitly forbids it in NODE_OPTIONS.
        # Record the workaround: the shipped default wrapper is not certified.
        out['explicit_node_expose_internals_required'] = True
        out['shipped_start_wrapper_verified'] = False
        p = start(['node', '--expose-internals', '/usr/local/bin/dsh', 'web', '--patch', '/usr/local/share/deepseek-harness/managed.cordis.patch.yml', '--port', '3080', '--no-open'], env)
        try:
            wait_ready(p, lambda: http(3080), seconds=90)
            out['gateway_health_verified'] = True
        finally:
            stop(p)
    elif TYPE == 'openclaw':
        out['version'] = run(['openclaw', '--version']).strip()
        run(['openclaw', 'setup', '--baseline', '--workspace', str(HOME / 'workspace')])
        env = dict(ENV, OPENCLAW_GATEWAY_TOKEN='synthetic-lab-token-only')
        p = start(['openclaw', 'gateway', 'run', '--allow-unconfigured', '--auth', 'token', '--bind', 'loopback', '--port', '18789'], env)
        try:
            wait_ready(p, lambda: run(['openclaw', 'gateway', 'health', '--json'], timeout=15, env=env))
            out['gateway_health_verified'] = True
        finally:
            stop(p)
    elif TYPE == 'workbuddy' and MODE == 'lite':
        env = dict(ENV, ELECTRON_RUN_AS_NODE='1', WORKBUDDY_APP_VERSION='5.3.14',
                   WORKBUDDY_WEB_SOCKET_PATH='/tmp/workbuddy.sock', WORKBUDDY_DOCS_LIFECYCLE_MODE='off',
                   WORKBUDDY_CONFIG_DIR=str(HOME / '.workbuddy'), WORKBUDDY_USER_DATA_DIR=str(HOME / '.workbuddy/app'))
        p = start(['/opt/workbuddy/electron', '/opt/workbuddy-web/server.js'], env)
        try:
            out['health'] = wait_ready(p, wb_health)
            out['gateway_health_verified'] = True
            out['version'] = '5.3.14 (bundled bridge configuration)'
        finally:
            stop(p)
    elif TYPE == 'workbuddy' and MODE == 'pro':
        out['electron_version'] = Path('/opt/workbuddy/version').read_text().strip()
        out['version'] = run(['/opt/workbuddy/electron', '-e', "console.log(require('/opt/workbuddy/resources/app.asar/package.json').version)"], env=dict(ENV, ELECTRON_RUN_AS_NODE='1')).strip()
        display = start(['/usr/bin/Xvfb', ':88', '-screen', '0', '1024x768x24', '-nolisten', 'tcp'])
        p = None
        try:
            wait_ready(display, lambda: Path('/tmp/.X11-unix/X88').stat(), seconds=15)
            p = start(['/usr/local/bin/start-workbuddy', '--disable-gpu', '--inspect=127.0.0.1:9229'], dict(ENV, DISPLAY=':88'))
            def ready():
                files = list((HOME / '.workbuddy').glob('workbuddy.db')) + list((HOME / '.workbuddy/app').rglob('Preferences'))
                if not files:
                    raise RuntimeError('native desktop state not initialized')
                return files
            wait_ready(p, ready)
            time.sleep(5)
            out['native_desktop_state_initialized'] = True
        finally:
            if p is not None:
                try:
                    # Ask this disposable desktop's Electron main process to
                    # quit normally. The debug port exists only on the private
                    # network-none loopback; this is not a Runtime Agent proof.
                    endpoint = json.loads(http(9229, '/json/list'))[0]['webSocketDebuggerUrl']
                    script = "const ws=new WebSocket(process.argv[1]);const t=setTimeout(()=>process.exit(1),10000);ws.onopen=()=>ws.send(JSON.stringify({id:1,method:'Runtime.evaluate',params:{expression:\"process.mainModule.require('electron').app.quit()\"}}));ws.onmessage=e=>{const r=JSON.parse(e.data);if(r.id===1){clearTimeout(t);if(r.error||r.result?.exceptionDetails){console.error(JSON.stringify(r));process.exit(2)}ws.close()}};ws.onclose=()=>{clearTimeout(t)};"
                    run(['/opt/workbuddy/electron', '-e', script, endpoint], timeout=15, env=dict(ENV, ELECTRON_RUN_AS_NODE='1'))
                    p.wait(timeout=30)
                finally:
                    stop(p)
            stop(display)
    return out


def inventory(home):
    result = {}
    for p in [home] + sorted(home.rglob('*')):
        s = p.lstat()
        item = {'mode': stat.S_IMODE(s.st_mode), 'uid': s.st_uid, 'gid': s.st_gid}
        if p.is_symlink():
            item.update(kind='symlink', target=os.readlink(p))
        elif p.is_dir():
            item.update(kind='directory', mtime_ns=s.st_mtime_ns)
        elif p.is_file():
            with p.open('rb') as f:
                digest = hashlib.file_digest(f, 'sha256').hexdigest()
            item.update(kind='file', size=s.st_size, sha256=digest, mtime_ns=s.st_mtime_ns)
        else:
            raise RuntimeError('unsupported native file: ' + str(p.relative_to(home)))
        item['xattrs'] = {k: os.getxattr(p, k, follow_symlinks=False).hex() for k in os.listxattr(p, follow_symlinks=False)}
        result[str(p.relative_to(home))] = item
    return result


def prepare():
    os.umask(0o077)
    os.chown(HOME, UID, UID)
    HOME.chmod(0o700)
    for d in ('workspace', '.config', '.cache', '.local/share'):
        (HOME / d).mkdir(parents=True, exist_ok=True, mode=0o700)
    for p in HOME.rglob('*'):
        os.chown(p, UID, UID)
    result = native_prepare()
    # The container's private PID namespace must contain no remaining writer.
    terminated_orphans = set()
    for attempt in range(200):
        live = []
        for p in Path('/proc').iterdir():
            if not p.name.isdecimal() or int(p.name) == os.getpid():
                continue
            try:
                if 'State:\tZ' not in (p / 'status').read_text():
                    live.append(int(p.name))
                    # Some WorkBuddy sidecars detach into another process
                    # group. Only this test UID in this private PID namespace
                    # may receive TERM, after the native parent has stopped.
                    if attempt == 50 and p.stat().st_uid == UID:
                        os.kill(int(p.name), signal.SIGTERM)
                        terminated_orphans.add(int(p.name))
            except FileNotFoundError:
                pass
        if not live:
            break
        time.sleep(.1)
    if live:
        raise RuntimeError('native writers remain: ' + str(live))
    result['detached_test_children_terminated'] = len(terminated_orphans)
    fixture = HOME / '.backup-lab-fixtures'
    fixture.mkdir(mode=0o700)
    for name, text in {
        'policy.json': '{"enabled":false}',
        'model-channel.json': json.dumps({'modelKey': 'fake-' + NAME, 'channelToken': 'fake-channel-' + NAME}),
        'tasks.json': json.dumps({'enabled': False, 'cron': '0 * * * *', 'owner': UID}),
        'skills/backup/SKILL.md': '# Synthetic test Skill\nNo commands.\n',
        '中文 空格/文档.txt': NAME + '\n合成备份恢复测试',
        'history.jsonl': ''.join(json.dumps({'user': UID, 'instance': NAME, 'message': i}) + '\n' for i in range(300)),
    }.items():
        path = fixture / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(text)
        path.chmod(0o600)
    os.symlink('skills/backup/SKILL.md', fixture / 'skill-link')
    # Preserve a committed, uncheckpointed WAL, not just an empty SQLite header.
    db = sqlite3.connect(fixture / 'sessions.sqlite')
    assert db.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
    db.execute('PRAGMA wal_autocheckpoint=0')
    db.execute('CREATE TABLE messages (id INTEGER PRIMARY KEY, owner INTEGER, instance TEXT)')
    db.executemany('INSERT INTO messages VALUES(?,?,?)', [(i, UID, NAME) for i in range(300)])
    db.commit()
    for p in [fixture] + list(fixture.rglob('*')):
        os.lchown(p, UID, UID)
    (LAB / 'native-result.json').write_text(json.dumps(result, indent=2))
    (LAB / 'inventory.json').write_text(json.dumps(inventory(HOME)))
    os._exit(0)  # Deliberately retain WAL; all committed rows must restore.


def compare():
    expected = json.loads((LAB / 'inventory.json').read_text())
    actual = inventory(HOME)
    changed = [k for k in actual.keys() | expected.keys() if actual.get(k) != expected.get(k)]
    if changed:
        raise RuntimeError('restored content/metadata mismatch: ' + ', '.join(sorted(changed)[:15]))
    native = 0
    for p in HOME.rglob('*'):
        if p.is_symlink() or not p.is_file():
            continue
        with p.open('rb') as f:
            if f.read(16) != b'SQLite format 3\0':
                continue
        # SQLite may need a writable SHM; never mutate the restored evidence.
        with tempfile.TemporaryDirectory() as td:
            dst = Path(td) / 'state.db'
            shutil.copyfile(p, dst)
            for suffix in ('-wal', '-shm'):
                if Path(str(p) + suffix).exists():
                    shutil.copyfile(str(p) + suffix, str(dst) + suffix)
            with sqlite3.connect(dst) as db:
                db.execute('PRAGMA query_only=ON')
                assert db.execute('PRAGMA quick_check').fetchall() == [('ok',)]
                if p == HOME / '.backup-lab-fixtures/sessions.sqlite':
                    assert db.execute('SELECT COUNT(*) FROM messages WHERE owner=? AND instance=?', (UID, NAME)).fetchone()[0] == 300
                else:
                    native += 1
    result = {'case': NAME, 'entries': len(actual), 'contents_permissions_ownership_mtimes_links_xattrs_verified': True,
              'native_sqlite_checked': native, 'synthetic_wal_messages': 300, 'source_independent': True}
    (LAB / 'metadata-result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


def native_readback():
    out = {'case': NAME, 'native_readback_verified': False}
    if TYPE == 'hermes':
        base, py = hermes_python()
        run([py, '-c', "import sys;sys.path.insert(0,sys.argv[1]);from hermes_state import SessionDB;db=SessionDB(read_only=True);m=db.get_messages('backup-lab-session');assert any(x['content']=='synthetic persistent message' for x in m);db.close()", base])
        out['native_readback_verified'] = True
    elif TYPE == 'opencode':
        env = dict(ENV, HOST='127.0.0.1', PORT='4096', CLAWMANAGER_GATEWAY_PORT='4096')
        p = start(['/usr/local/bin/start-opencode-pro-web' if MODE == 'pro' else '/usr/local/bin/start-opencode-web'], env)
        try:
            wait_ready(p, lambda: http(4096, '/global/health'))
            original = json.loads((LAB / 'native-result.json').read_text())
            restored = json.loads(http(4096, '/session/' + original['native_session_id']))
            assert restored['title'] == 'Synthetic backup lab ' + NAME
            out['native_readback_verified'] = True
        finally:
            stop(p)
    elif TYPE == 'deepseek-harness':
        env = dict(ENV, DSH_BIND_HOST='127.0.0.1', CLAWMANAGER_LLM_BASE_URL='http://127.0.0.1:9/v1',
                   CLAWMANAGER_LLM_API_KEY='synthetic-not-a-real-key', CLAWMANAGER_LLM_MODEL='["synthetic-lab-model"]', OPENAI_MODEL='synthetic-lab-model')
        p = start(['node', '--expose-internals', '/usr/local/bin/dsh', 'web', '--patch', '/usr/local/share/deepseek-harness/managed.cordis.patch.yml', '--port', '3080', '--no-open'], env)
        try:
            wait_ready(p, lambda: http(3080), seconds=90)
            out['restored_gateway_restart_verified'] = True
            out['image_dependency_links_usable'] = True
        finally:
            stop(p)
    (LAB / 'native-readback.json').write_text(json.dumps(out, indent=2))


{'prepare': prepare, 'compare': compare, 'native-readback': native_readback}[sys.argv[1]]()
