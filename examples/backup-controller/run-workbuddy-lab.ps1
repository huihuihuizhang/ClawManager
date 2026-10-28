# Local synthetic WorkBuddy Lite data-plane test. No kubeconfig or remote server.
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$fixture=Join-Path $PSScriptRoot 'workbuddy-lab-fixtures.py'
$suffix='workbuddy-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$labRoot=Join-Path $repo ('.codex-temp/backup-lab/'+$suffix)
$resource='cm-backup-lab-'+$suffix
$image='sha256:e2eff0ff74b146b126cc88f05f0ee7f863c40041de2849d6c304bd40fe0ce496'
$mysql='sha256:7791889374e752a470ed491c5c7684bf91d64c2472721539bef3a64f5276e074'
function Invoke-WBDocker {
    & docker --context desktop-linux @args
    if($LASTEXITCODE -ne 0){throw 'Isolated WorkBuddy Docker operation failed; lab retained for inspection.'}
}
$endpoint=(& docker context inspect desktop-linux --format '{{.Endpoints.docker.Host}}').Trim()
if($LASTEXITCODE -ne 0 -or $endpoint -ne 'npipe:////./pipe/dockerDesktopLinuxEngine'){throw 'Expected local Docker Desktop Linux engine.'}
foreach($ref in @($image,$mysql)){Invoke-WBDocker image inspect $ref --format '{{.Id}}'}
$location=Get-Location
$savedEnv=@{}
foreach($key in @('GOOS','GOARCH','CGO_ENABLED','GOPROXY','GOSUMDB','GOTOOLCHAIN')){$savedEnv[$key]=[Environment]::GetEnvironmentVariable($key,'Process')}
$active=[Collections.Generic.List[string]]::new()
try {
    Set-Location (Join-Path $repo 'backend')
    $env:GOTOOLCHAIN='local'; $env:GOPROXY='off'; $env:GOSUMDB='off'; $env:GOOS='windows'; $env:GOARCH='amd64'
    & go run ./cmd/backup-lab --action prepare --suite workbuddy --root $labRoot
    if($LASTEXITCODE -ne 0){throw 'Lab preparation failed.'}
    $env:GOOS='linux'; $env:CGO_ENABLED='0'
    & go build -trimpath -o (Join-Path $labRoot 'bin/backup-lab') ./cmd/backup-lab
    if($LASTEXITCODE -ne 0){throw 'Linux lab runner build failed.'}
    $manifest=[ordered]@{schema='workbuddy-isolated-backup-lab.v1';root=$labRoot;image=$image;mysql_image=$mysql;docker_context='desktop-linux';network=$resource;source_volume=$resource+'-source';restore_volume=$resource+'-restore';database_volume=$resource+'-mysql';agents=@{};runtime_agent_lifecycle_verified=$false;identity_table_migration_verified=$false}
    foreach($v in @('source','restore','mysql')){Invoke-WBDocker volume create --label 'clawmanager.backup-lab=synthetic' ($resource+'-'+$v)}
    Invoke-WBDocker run --rm --pull never --network none --read-only --mount "type=volume,source=$resource-source,target=/workspaces" --mount "type=bind,source=$fixture,target=/fixture.py,readonly" --entrypoint python3 $image /fixture.py init
    foreach($item in @(@{name='workbuddy-a';uid=12001},@{name='workbuddy-b';uid=12002})) {
        $name=$item.name; $uid=$item.uid; $homePath='/workspaces/'+$name; $container=$resource+'-'+$name
        # Direct native daemon/web bridge test under a real non-root Linux UID.
        # This deliberately does not claim Runtime Agent/bwrap/tun certification.
        Invoke-WBDocker run -d --name $container --label 'clawmanager.backup-lab=synthetic' --pull never --network none --read-only --user "${uid}:${uid}" --cap-drop ALL --security-opt no-new-privileges --memory 2g --pids-limit 256 --tmpfs '/tmp:rw,size=256m,mode=1777' --mount "type=volume,source=$resource-source,target=/workspaces" --mount "type=bind,source=$fixture,target=/fixture.py,readonly" --env "HOME=$homePath" --env "XDG_CONFIG_HOME=$homePath/.config" --env "XDG_DATA_HOME=$homePath/.local/share" --env "XDG_CACHE_HOME=$homePath/.cache" --env ELECTRON_RUN_AS_NODE=1 --env WORKBUDDY_WEB_SOCKET_PATH=/tmp/workbuddy.sock --env WORKBUDDY_DOCS_LIFECYCLE_MODE=off --env WORKBUDDY_APP_VERSION=5.3.14 --env "WORKBUDDY_CONFIG_DIR=$homePath/.workbuddy" --env "WORKBUDDY_USER_DATA_DIR=$homePath/.workbuddy/app" --entrypoint /usr/bin/tini $image -- /opt/workbuddy/electron /opt/workbuddy-web/server.js
        $active.Add($container)
        $healthy=$false
        for($i=0;$i -lt 30;$i++) {
            $health=& docker --context desktop-linux exec $container python3 /fixture.py health 2>&1
            if($LASTEXITCODE -eq 0){$healthy=$true;break}
            $running=& docker --context desktop-linux inspect $container --format '{{.State.Running}}'
            if($running -eq 'false'){break}
            Start-Sleep -Seconds 2
        }
        if(!$healthy){throw "WorkBuddy native daemon failed health check in $container. Inspect its synthetic container logs."}
        $manifest.agents[$name]=@{uid=$uid;gid=$uid;health=($health -join '' | ConvertFrom-Json);stopped=$false}
        Invoke-WBDocker stop --time 20 $container
        $state=Invoke-WBDocker inspect $container --format '{{.State.Running}} {{.State.ExitCode}}'
        if(($state -join '').Trim() -ne 'false 0'){throw 'WorkBuddy did not stop cleanly.'}
        $active.Remove($container) | Out-Null
        $manifest.agents[$name].stopped=$true
    }
    Invoke-WBDocker run --rm --pull never --network none --read-only --mount "type=volume,source=$resource-source,target=/workspaces" --mount "type=bind,source=$fixture,target=/fixture.py,readonly" --entrypoint python3 $image /fixture.py seed
    foreach($item in @(@{uid=12001;own='workbuddy-a';other='workbuddy-b'},@{uid=12002;own='workbuddy-b';other='workbuddy-a'})) {
        $script='test -r /workspaces/'+$item.own+'/.backup-lab-fixtures/config.json && ! test -r /workspaces/'+$item.other+'/.backup-lab-fixtures/config.json'
        Invoke-WBDocker run --rm --pull never --network none --read-only --user "$($item.uid):$($item.uid)" --cap-drop ALL --mount "type=volume,source=$resource-source,target=/workspaces,readonly" --entrypoint /bin/sh $image -c $script
    }
    $manifest.source_cross_uid_read_denied=$true
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $labRoot 'environment.json') -Encoding utf8
    Invoke-WBDocker run --rm --pull never --network none --read-only --mount "type=volume,source=$resource-source,target=/workspaces,readonly" --mount "type=bind,source=$labRoot,target=/lab" --mount "type=bind,source=$fixture,target=/fixture.py,readonly" --entrypoint python3 $image /fixture.py record
    Invoke-WBDocker network create --internal --label 'clawmanager.backup-lab=synthetic' $resource
    Invoke-WBDocker run -d --pull never --name ($resource+'-mysql') --label 'clawmanager.backup-lab=synthetic' --network $resource --network-alias mysql --memory 1g --env MYSQL_ROOT_PASSWORD_FILE=/lab-creds/mysql-root --mount "type=volume,source=$resource-mysql,target=/var/lib/mysql" --mount "type=bind,source=$labRoot/credentials,target=/lab-creds,readonly" --mount "type=bind,source=$labRoot/tls,target=/lab-tls,readonly" --mount "type=bind,source=$labRoot/init,target=/docker-entrypoint-initdb.d,readonly" $mysql --ssl-ca=/lab-tls/ca.pem --ssl-cert=/lab-tls/server.pem --ssl-key=/lab-tls/server-key.pem --require-secure-transport=ON --partial-revokes=ON --innodb-buffer-pool-size=64M
    $active.Add($resource+'-mysql')
    Invoke-WBDocker exec --user 0:0 ($resource+'-mysql') /bin/sh -c 'umask 077; cp /lab-creds/root.cnf /tmp/lab-root.cnf; chmod 600 /tmp/lab-root.cnf'
    $ready=$false
    for($i=0;$i -lt 40;$i++) {
        $check=& docker --context desktop-linux exec ($resource+'-mysql') mysql --defaults-extra-file=/tmp/lab-root.cnf --batch --skip-column-names -e 'SELECT IF(@@GLOBAL.skip_networking=0,COUNT(*),-1) FROM cm_source_backup_lab.instances' 2>&1
        if($LASTEXITCODE -eq 0 -and ($check -join '').Trim() -eq '2'){$ready=$true;break}
        Start-Sleep -Seconds 2
    }
    if(!$ready){throw 'Isolated MySQL initialization failed.'}
    Invoke-WBDocker exec ($resource+'-mysql') mysql --defaults-extra-file=/tmp/lab-root.cnf -e 'SET GLOBAL read_only=ON; SET GLOBAL super_read_only=ON;'
    Invoke-WBDocker run --rm --pull never --network $resource --read-only --tmpfs '/tmp:rw,size=64m' --mount "type=bind,source=$labRoot,target=/lab" --mount "type=bind,source=$labRoot/credentials,target=/lab/credentials,readonly" --mount "type=volume,source=$resource-source,target=/source,readonly" --entrypoint /lab/bin/backup-lab $mysql --action capture --root /lab
    Invoke-WBDocker stop --time 20 ($resource+'-mysql')
    $active.Remove($resource+'-mysql') | Out-Null
    $verifyRoot=Join-Path $labRoot 'verifier'
    New-Item -ItemType Directory -Path $verifyRoot | Out-Null
    Invoke-WBDocker run --rm --pull never --network none --read-only --mount "type=bind,source=$verifyRoot,target=/lab" --mount "type=bind,source=$labRoot/bin,target=/lab/bin,readonly" --mount "type=bind,source=$labRoot/credentials,target=/lab/credentials,readonly" --mount "type=bind,source=$labRoot/artifacts,target=/lab/artifacts,readonly" --mount "type=bind,source=$labRoot/expected.json,target=/lab/expected.json,readonly" --mount "type=volume,source=$resource-restore,target=/lab/verification" --entrypoint /lab/bin/backup-lab $mysql --action verify --root /lab
    Copy-Item -LiteralPath (Join-Path $verifyRoot 'result.json') -Destination (Join-Path $labRoot 'result.json')
    Invoke-WBDocker run --rm --pull never --network none --read-only --mount "type=volume,source=$resource-restore,target=/verification,readonly" --mount "type=bind,source=$verifyRoot,target=/lab" --mount "type=bind,source=$labRoot/workbuddy-inventory.json,target=/lab/workbuddy-inventory.json,readonly" --mount "type=bind,source=$fixture,target=/fixture.py,readonly" --entrypoint python3 $image /fixture.py compare
    Copy-Item -LiteralPath (Join-Path $verifyRoot 'workbuddy-result.json') -Destination (Join-Path $labRoot 'workbuddy-result.json')
    # The Linux document SDK uses Wine. Probe its real prefix separately; the
    # current archive must report the unsupported layout, never silently skip it.
    Invoke-WBDocker run --rm --pull never --network none --read-only --user 12001:12001 --cap-drop ALL --security-opt no-new-privileges --memory 3g --pids-limit 256 --tmpfs '/tmp:rw,size=128m,mode=1777' --tmpfs '/source:rw,size=2g,uid=12001,gid=12001,mode=0700' --mount "type=bind,source=$verifyRoot,target=/lab" --mount "type=bind,source=$labRoot/bin,target=/lab/bin,readonly" --mount "type=bind,source=$fixture,target=/fixture.py,readonly" --entrypoint python3 $image /fixture.py wine
    Copy-Item -LiteralPath (Join-Path $verifyRoot 'workbuddy-wine-result.json') -Destination (Join-Path $labRoot 'workbuddy-wine-result.json')
    Write-Output 'Baseline checks passed. Generic archives correctly reject Wine; run run-workbuddy-wine-lab.ps1 for the opt-in Wine adapter. Identity migration remains unverified.'
    Write-Output "WorkBuddy lab results: $labRoot"
} finally {
    foreach($name in $active){& docker --context desktop-linux stop --time 20 $name | Out-Null}
    Set-Location $location
    foreach($key in $savedEnv.Keys){[Environment]::SetEnvironmentVariable($key,$savedEnv[$key],'Process')}
}
