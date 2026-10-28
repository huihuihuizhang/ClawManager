"""Physical capacity feed for the task-owned native test, never a shared server.

Runs the production capacity collector beside the actual MySQL data mount under
an exact SELECT-only account. Only its unmodified report crosses into the test
Pod. Fixture credentials are generated in memory and never printed.
"""
import hashlib
import json
import re
import secrets
import subprocess
import threading


class NativeCapacity:
    def __init__(self, mysql, kubectl, request):
        self.mysql, self.kubectl = mysql, kubectl
        self.request = request
        self.stop_event = threading.Event()
        self.error = None
        self.thread = None

        self.samples = 0
        self.user = 'cap_' + secrets.token_hex(10)
        self.directory = '/tmp/' + self.user
        database, server, target = (request.get(k, '') for k in ('database', 'server_uuid', 'report_file'))
        if not re.fullmatch(r'cm_admission_[a-f0-9]{32}', database) or not re.fullmatch(r'[a-f0-9-]{36}', server):
            raise RuntimeError('native capacity source identity rejected')
        if not re.fullmatch(r'/tmp/TestPublicCaptureNativeMySQLKubernetes[a-zA-Z0-9_/-]+/capacity.json', target) or '..' in target:
            raise RuntimeError('native capacity report target rejected')
        info = json.loads(self.read(['docker', 'inspect', mysql]))[0]
        if info['Config']['Labels'].get('codex.task') != 'backup-team-integration' or '/var/lib/mysql' not in info['HostConfig'].get('Tmpfs', {}):
            raise RuntimeError('native capacity container ownership rejected')
        observed = self.sql('SELECT @@server_uuid;').strip()
        if observed != server:
            raise RuntimeError('native capacity live server differs')
        tables = self.sql("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database + "' AND (LEFT(TABLE_NAME,14)='system_backup_' OR LEFT(TABLE_NAME,15)='system_restore_' OR TABLE_NAME='audit_logs') ORDER BY TABLE_NAME;").splitlines()
        if not tables or any(not re.fullmatch(r'[a-zA-Z0-9_]+', t) for t in tables):
            raise RuntimeError('native capacity table inventory rejected')
        password = secrets.token_hex(24)
        self.sql("CREATE USER '" + self.user + "'@'localhost' IDENTIFIED BY '" + password + "';\n" + '\n'.join("GRANT SELECT ON `" + database + "`.`" + t + "` TO '" + self.user + "'@'localhost';" for t in tables))
        self.call(['docker', 'exec', mysql, 'mkdir', '-m', '0700', self.directory])
        config = {'server_uuid': server, 'database': database, 'user': self.user, 'data_directory': '/var/lib/mysql', 'tables': tables}
        raw = json.dumps(config, separators=(',', ':')).encode()
        self.write_mysql(self.directory + '/capacity.json', raw)
        socket = self.sql('SELECT @@socket;').strip()
        if not socket.startswith('/') or any(c in socket for c in ')\n\r\x00'):
            raise RuntimeError('native MySQL socket rejected')
        self.write_mysql(self.directory + '/source.dsn', (self.user + ':' + password + '@unix(' + socket + ')/' + database).encode())
        self.call(['docker','exec',mysql,'chown','mysql:mysql',self.directory,self.directory+'/capacity.json',self.directory+'/source.dsn'])
        self.digest = hashlib.sha256(raw).hexdigest()

    @staticmethod
    def call(args, **kwargs):
        return subprocess.run(args, check=True, capture_output=True, timeout=15, **kwargs)

    @classmethod
    def read(cls, args):
        return cls.call(args).stdout.decode().strip()

    def sql(self, body):
        return self.call(['docker', 'exec', '-i', self.mysql, 'mysql', '-N', '-B', '-uroot'], input=body.encode()).stdout.decode()

    def write_mysql(self, path, raw):
        self.call(['docker', 'exec', '-i', self.mysql, 'sh', '-c', 'umask 077; cat > "$1"', 'sh', path], input=raw)

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            while not self.stop_event.is_set():
                raw = self.call(['docker', 'exec', '--user','mysql',self.mysql, 'env', 'SYSTEM_BACKUP_REGISTRATION_DSN_FILE=' + self.directory + '/source.dsn', 'SYSTEM_BACKUP_CAPACITY_CONFIG_SHA256=' + self.digest, '/tmp/native-capacity', '--check-capacity-source', '--capacity-config', self.directory + '/capacity.json']).stdout
                report = json.loads(raw)
                if report['server_uuid'] != self.request['server_uuid'] or report['database'] != self.request['database']:
                    raise RuntimeError('capacity report identity changed')
                self.call(self.kubectl + ['-n', 'cm-backup-m0m2-native', 'exec', '-i', 'native-controller', '--', '/bin/sh', '-c', 'umask 077; cat > "$1.next" && mv "$1.next" "$1"', 'sh', self.request['report_file']], input=raw)
                self.samples += 1
                self.stop_event.wait(0.5)
        except Exception:
            # Driver/SQL stderr can contain source details. Retain only a closed
            # local failure code; stale/missing reports make admission fail.
            self.error = 'physical_capacity_feed_failed'

    def close(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=20)
            if self.thread.is_alive():
                raise RuntimeError('physical capacity observer did not stop')
        self.sql("DROP USER IF EXISTS '" + self.user + "'@'localhost';")
