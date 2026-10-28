"""Synthetic WorkBuddy lab fixtures and Linux metadata/SQLite verification.

Fixed lab paths only. Never contacts a network or reads a real user's HOME.
"""
import hashlib
import json
import os
import signal
import shutil
from pathlib import Path
import socket
import sqlite3
import stat
import subprocess
import sys
import time
import tempfile
import zipfile

HOMES = [("workbuddy-a", 12001, "instance-7"), ("workbuddy-b", 12002, "instance-8")]


def init():
    for name, uid, _ in HOMES:
        home = Path("/workspaces") / name
        home.mkdir(mode=0o700)
        os.chown(home, uid, uid)


def health():
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(8)
        s.connect("/tmp/workbuddy.sock")
        s.sendall(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        data = b""
        while True:
            block = s.recv(4096)
            if not block:
                break
            data += block
            if len(data) > 16384:
                raise RuntimeError("unexpected health response")
    headers, body = data.split(b"\r\n\r\n", 1)
    result = json.loads(body)
    if b" 200 " not in headers.split(b"\r\n")[0] or not result.get("daemonReady") or result.get("daemonExited"):
        raise RuntimeError("WorkBuddy daemon not ready")
    print(json.dumps(result))


def seed():
    # Leave a committed SQLite WAL by exiting without normal connection cleanup.
    # This is an explicit test database, not a guessed vendor database schema.
    connections = []
    for name, uid, _ in HOMES:
        home = Path("/workspaces") / name
        fixture = home / ".backup-lab-fixtures"
        fixture.mkdir(mode=0o700)
        contents = {
            "config.json": json.dumps({"model": "synthetic", "apiKey": "fake-" + name, "channelToken": "fake-channel", "enabled": False}),
            "tasks.json": json.dumps({"enabled": False, "cron": "0 * * * *", "instance": name}),
            "skills/test/SKILL.md": "# Synthetic skill\nOnly for backup testing.\n",
            "history/session.jsonl": "".join(json.dumps({"role": "user", "content": f"{name} message {i}"}) + "\n" for i in range(300)),
            "workspace/中文 空格/说明.txt": "合成测试文档\n" + name,
            "workspace/empty": "",
            ".credentials": "synthetic-token=" + name,
            "workspace/run.sh": "#!/bin/sh\nexit 0\n",
        }
        for rel, value in contents.items():
            p = fixture / rel
            p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            p.write_text(value, encoding="utf-8")
            p.chmod(0o600)
        (fixture / "workspace/run.sh").chmod(0o700)
        (fixture / "workspace/readonly.bin").write_bytes(bytes(range(256)) * 8192)
        (fixture / "workspace/readonly.bin").chmod(0o400)
        many = fixture / "workspace/many"
        many.mkdir(mode=0o700)
        for i in range(500):
            p = many / f"file-{i:04}.txt"
            p.write_text(f"{name}:{i}\n")
            p.chmod(0o600)
        os.symlink("skills/test/SKILL.md", fixture / "skill-link")
        db = sqlite3.connect(fixture / "sessions.sqlite")
        assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        db.execute("PRAGMA wal_autocheckpoint=0")
        db.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, instance TEXT NOT NULL, content TEXT NOT NULL)")
        db.executemany("INSERT INTO messages(instance,content) VALUES(?,?)", [(name, f"message {i}") for i in range(300)])
        db.commit()
        connections.append(db)
        # Restrict just our fixture tree. Native application metadata is untouched.
        for base, dirs, files in os.walk(fixture):
            os.chown(base, uid, uid)
            for item in dirs + files:
                os.lchown(Path(base) / item, uid, uid)
        for suffix in ("", "-wal", "-shm"):
            (fixture / ("sessions.sqlite" + suffix)).chmod(0o600)
    os._exit(0)


def inventory(home, times=False):
    result = {}
    for p in [home] + sorted(home.rglob("*")):
        s = p.lstat()
        item = {"mode": stat.S_IMODE(s.st_mode), "uid": s.st_uid, "gid": s.st_gid}
        if stat.S_ISLNK(s.st_mode):
            item.update(kind="symlink", target=os.readlink(p))
        elif stat.S_ISDIR(s.st_mode):
            item.update(kind="directory")
        elif stat.S_ISREG(s.st_mode):
            with p.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            item.update(kind="file", size=s.st_size, sha256=digest)
        else:
            raise RuntimeError("unsupported native file type: " + str(p.relative_to(home)))
        if times and not stat.S_ISLNK(s.st_mode):
            item['mtime_ns'] = s.st_mtime_ns
        if times:
            item['xattrs'] = {name: os.getxattr(p, name, follow_symlinks=False).hex() for name in os.listxattr(p, follow_symlinks=False)}
        result[str(p.relative_to(home))] = item
    return result


def record():
    result = {name: inventory(Path("/workspaces") / name) for name, _, _ in HOMES}
    for name, _, _ in HOMES:
        assert result[name][".backup-lab-fixtures/sessions.sqlite-wal"]["size"] > 0
    Path("/lab/workbuddy-inventory.json").write_text(json.dumps(result, sort_keys=True))
    print(json.dumps({"entries": {k: len(v) for k, v in result.items()}, "committed_wal_present": True}))


def compare():
    expected = json.loads(Path("/lab/workbuddy-inventory.json").read_text())
    native_count = 0
    fixture_rows = 0
    for name, uid, target in HOMES:
        home = Path("/verification") / target
        actual = inventory(home)
        if actual != expected[name]:
            changed = sorted(k for k in actual.keys() | expected[name].keys() if actual.get(k) != expected[name].get(k))
            raise RuntimeError("restored bytes/ownership/modes/links differ: " + ",".join(changed[:10]))
        assert actual["."]["uid"] == uid and actual["."]["mode"] == 0o700
        other = "instance-8" if target == "instance-7" else "instance-7"
        subprocess.run([sys.executable, "-c", "from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes();\ntry: Path(sys.argv[2]).read_bytes()\nexcept PermissionError: pass\nelse: raise RuntimeError('cross-UID read allowed')", str(home / ".backup-lab-fixtures/config.json"), str(Path('/verification') / other / '.backup-lab-fixtures/config.json')], check=True, user=uid, group=uid, extra_groups=[])
        # Read-only SQLite recovery includes the preserved committed WAL.
        for p in sorted(home.rglob("*")):
            if p.is_symlink() or not p.is_file():
                continue
            with p.open("rb") as f:
                header = f.read(16)
            if header != b"SQLite format 3\x00":
                continue
            with sqlite3.connect(p.as_uri() + "?mode=ro", uri=True) as db:
                assert db.execute("PRAGMA quick_check").fetchall() == [("ok",)]
                if p == home / ".backup-lab-fixtures/sessions.sqlite":
                    count = db.execute("SELECT COUNT(*) FROM messages WHERE instance=?", (name,)).fetchone()[0]
                    assert count == 300
                    fixture_rows += count
                else:
                    native_count += 1
    report = {"linux_ownership_modes_links_verified": True, "restored_cross_uid_read_denied": True, "fixture_wal_rows_recovered": fixture_rows, "native_sqlite_databases_checked": native_count, "identity_table_migration_verified": False, "vendor_session_semantics_verified": False}
    Path("/lab/workbuddy-result.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report))


def wine():
    home = Path("/source/workbuddy-wine")
    prefix = home / ".local/share/workbuddy-editor-sdk-wine"
    prefix.mkdir(parents=True, mode=0o700)
    env = dict(os.environ, HOME=str(home), WINEPREFIX=str(prefix), WINEARCH="win64", WINEDEBUG="-all", WINEDLLOVERRIDES="mscoree,mshtml=")
    result = subprocess.run(["/opt/workbuddy-lite/wine-loader", "wineboot", "-u"], env=env, capture_output=True, timeout=90)
    if result.returncode != 0:
        raise RuntimeError("isolated Wine initialization failed with exit " + str(result.returncode))
    for option in ("-k", "-w"):
        stopped = subprocess.run(["/usr/lib/x86_64-linux-gnu/wine/wineserver", option], env=env, timeout=15)
        # Wine may already have exited after initialization; verify that below.
        if stopped.returncode not in (0, 1):
            raise RuntimeError("Wine stop operation failed")
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal() or int(process.name) == os.getpid():
            continue
        try:
            status = (process / 'status').read_text()
        except FileNotFoundError:
            continue
        # This dedicated container has a private PID namespace. Require every
        # process other than this verifier to have exited, without reading env.
        if 'State:\tZ' not in status:
            raise RuntimeError('Wine prefix still has a live process')
    subprocess.run(["/lab/bin/backup-lab", "--action", "probe-workbuddy-wine", "--root", "/lab"], check=True, timeout=70)


def wine_env(home):
    return dict(os.environ, HOME=str(home), WINEPREFIX=str(home / '.local/share/workbuddy-editor-sdk-wine'), WINEARCH='win64', WINEDEBUG='-all', WINEDLLOVERRIDES='mscoree,mshtml=')


def wine_command(env, *args):
    result = subprocess.run(['/opt/workbuddy-lite/wine-loader', *args], env=env, capture_output=True, timeout=90)
    if result.returncode != 0:
        raise RuntimeError('isolated Wine command failed: ' + args[0] + ' exit=' + str(result.returncode))
    return result.stdout.decode('utf-8', errors='replace')


def wine_stop(env):
    for flag in ('-k', '-w'):
        result = subprocess.run(['/usr/lib/x86_64-linux-gnu/wine/wineserver', flag], env=env, timeout=20)
        if result.returncode not in (0, 1):
            raise RuntimeError('Wine stop failed')
    for _ in range(100):
        live = []
        for process in Path('/proc').iterdir():
            if not process.name.isdecimal() or int(process.name) == os.getpid():
                continue
            try:
                status = (process / 'status').read_text()
            except FileNotFoundError:
                continue
            if 'State:\tZ' not in status:
                live.append(process.name)
        if not live:
            return
        time.sleep(0.1)
    raise RuntimeError('Isolated native processes have not exited: ' + ','.join(live))


def wine_prepare():
    os.umask(0o077)
    home = Path('/source/workbuddy-wine')
    home.mkdir(mode=0o700)
    prefix = home / '.local/share/workbuddy-editor-sdk-wine'
    prefix.mkdir(parents=True, mode=0o700)
    env = wine_env(home)
    wine_command(env, 'wineboot', '-u')
    try:
        wine_command(env, 'reg', 'add', r'HKCU\Software\BackupLab', '/v', 'Marker', '/t', 'REG_SZ', '/d', 'persisted-from-source', '/f')
    finally:
        wine_stop(env)
    native_env = dict(env, ELECTRON_RUN_AS_NODE='1', WORKBUDDY_APP_VERSION='5.3.14', WORKBUDDY_WEB_SOCKET_PATH='/tmp/workbuddy.sock', WORKBUDDY_DOCS_LIFECYCLE_MODE='off', WORKBUDDY_CONFIG_DIR=str(home / '.workbuddy'), WORKBUDDY_USER_DATA_DIR=str(home / '.workbuddy/app'), XDG_CONFIG_HOME=str(home / '.config'), XDG_CACHE_HOME=str(home / '.cache'), XDG_DATA_HOME=str(home / '.local/share'))
    # Include actual native SQLite/config state in the SAME captured home as
    # the document SDK, while keeping Runtime Agent and external calls out.
    with Path('/lab/wine-native-init.log').open('wb') as log:
        native = subprocess.Popen(['/opt/workbuddy/electron', '/opt/workbuddy-web/server.js'], env=native_env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            ready = False
            for _ in range(30):
                if native.poll() is not None:
                    break
                try:
                    health()
                    ready = True
                    break
                except (OSError, RuntimeError):
                    time.sleep(2)
            if not ready:
                raise RuntimeError('WorkBuddy native state initialization failed')
        finally:
            native.terminate()
            try:
                code = native.wait(timeout=20)
            except subprocess.TimeoutExpired:
                native.kill()
                native.wait(timeout=5)
                raise RuntimeError('WorkBuddy native initialization did not stop cleanly')
            if code != 0:
                raise RuntimeError('WorkBuddy native initializer exit=' + str(code))
            # End only the process group created by this synthetic initializer.
            # This is test harness cleanup, not a Runtime Agent stop proof.
            try:
                os.killpg(native.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            wine_stop(env)
    docs = prefix / 'drive_c/backup-lab'
    docs.mkdir(mode=0o700)
    (docs / 'document.txt').write_text('synthetic-wine-document\n')
    (docs / '中文文档.txt').write_text('隔离文档组件备份恢复测试\n')
    # Minimal OOXML fixture: no macros, external links, credentials or real data.
    with zipfile.ZipFile(docs / 'document.docx', 'w', zipfile.ZIP_DEFLATED) as doc:
        doc.writestr('[Content_Types].xml', '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        doc.writestr('_rels/.rels', '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        doc.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Synthetic Wine document</w:t></w:r></w:p></w:body></w:document>')
    (home / 'backup-lab-policy.json').write_text('{"enabled":false}')
    expected = inventory(home, times=True)
    Path('/lab/wine-inventory.json').write_text(json.dumps(expected, sort_keys=True))
    print(json.dumps({'wine_initialized': True, 'entries': len(expected), 'bytes': sum(x.get('size', 0) for x in expected.values()), 'uid': os.getuid()}))


def wine_compare():
    expected = json.loads(Path('/lab/wine-inventory.json').read_text())
    actual = inventory(Path('/target'), times=True)
    if expected != actual:
        changed = sorted(k for k in actual.keys() | expected.keys() if actual.get(k) != expected.get(k))
        raise RuntimeError('Wine metadata/content mismatch: ' + ','.join(changed[:12]))
    native_databases = 0
    for name in ('.workbuddy/workbuddy.db', '.workbuddy/edge-sync-mapping-v2.db'):
        p = Path('/target') / name
        # A valid WAL backup can lack SHM (SQLite recreates it on open). Verify
        # a disposable complete DB/WAL/SHM copy, keeping the restored volume RO.
        with tempfile.TemporaryDirectory(prefix='wine-sqlite-check-') as scratch:
            check = Path(scratch) / 'state.db'
            for suffix in ('', '-wal', '-shm'):
                source = Path(str(p) + suffix)
                if source.exists():
                    shutil.copyfile(source, Path(str(check) + suffix))
            with sqlite3.connect(check) as db:
                db.execute('PRAGMA query_only=ON')
                assert db.execute('PRAGMA quick_check').fetchall() == [('ok',)]
                native_databases += 1
    report = {'linux_ownership_modes_mtimes_links_verified': True, 'extended_attributes_verified': True, 'wine_file_entries_verified': len(expected), 'native_sqlite_databases_checked': native_databases, 'sqlite_recovery_checked_on_disposable_copies': True, 'source_not_mounted': True}
    Path('/lab/wine-metadata-result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))


def wine_smoke():
    home = Path('/source/workbuddy-wine')
    env = wine_env(home)
    try:
        registry = wine_command(env, 'reg', 'query', r'HKCU\Software\BackupLab', '/v', 'Marker')
        assert 'persisted-from-source' in registry
        contents = wine_command(env, 'cmd', '/c', 'type', r'C:\backup-lab\document.txt')
        assert 'synthetic-wine-document' in contents
        root_mapping = wine_command(env, 'cmd', '/c', 'type', r'Z:\source\workbuddy-wine\backup-lab-policy.json')
        assert '"enabled":false' in root_mapping
        with zipfile.ZipFile(home / '.local/share/workbuddy-editor-sdk-wine/drive_c/backup-lab/document.docx') as doc:
            assert 'Synthetic Wine document' in doc.read('word/document.xml').decode()
    finally:
        wine_stop(env)
    report = {'restored_registry_readable': True, 'restored_c_drive_document_readable': True, 'restored_z_maps_isolated_container_root': True, 'docx_fixture_readable': True, 'wine_processes_stopped': True, 'native_editor_editing_verified': False, 'agent_started': False}
    Path('/lab/wine-runtime-result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))


if __name__ == "__main__":
    {"init": init, "health": health, "seed": seed, "record": record, "compare": compare, "wine": wine, "wine-prepare": wine_prepare, "wine-compare": wine_compare, "wine-smoke": wine_smoke}[sys.argv[1]]()
