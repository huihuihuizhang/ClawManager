# Explicit scope: four synthetic users plus eight non-WorkBuddy instances, or
# two WorkBuddy Lite instances using the versioned observed UID schema.
param([Parameter(Mandatory=$true)][string[]]$MatrixRoots,[ValidateSet('mixed','workbuddy-identity')][string]$Suite='mixed')
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$allowedRoot=[IO.Path]::GetFullPath((Join-Path $repo '.codex-temp/backup-lab'))+[IO.Path]::DirectorySeparatorChar
$modes=@('openclaw-lite','openclaw-pro','hermes-lite','hermes-pro','opencode-lite','opencode-pro','deepseek-harness-lite','deepseek-harness-pro')
if($Suite -eq 'workbuddy-identity'){$modes=@('workbuddy-lite')}
$instanceCount=8
if($Suite -eq 'workbuddy-identity'){$instanceCount=2}
$sources=@{}
function Invoke-MixedDocker {
    & docker --context desktop-linux @args
    if($LASTEXITCODE -ne 0){throw 'Mixed isolated lab Docker operation failed; artifacts retained.'}
}
$endpoint=(& docker context inspect desktop-linux --format '{{.Endpoints.docker.Host}}').Trim()
if($LASTEXITCODE -ne 0 -or $endpoint -ne 'npipe:////./pipe/dockerDesktopLinuxEngine'){throw 'Expected local Docker Desktop Linux engine.'}
foreach($root in $MatrixRoots){
    $resolved=[IO.Path]::GetFullPath($root)
    if(!$resolved.StartsWith($allowedRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Only this workspace synthetic matrix reports are accepted.'}
    $report=Get-Content -LiteralPath (Join-Path $resolved 'matrix-result.json') -Raw | ConvertFrom-Json
    foreach($case in $report.cases){
        if($case.case -in $modes -and $case.status -eq 'passed'){
            if($case.source_volume -notmatch '^cm-backup-lab-matrix-[a-z0-9-]+-source$'){throw 'Unexpected source volume.'}
            $label=Invoke-MixedDocker volume inspect $case.source_volume --format '{{index .Labels "clawmanager.backup-lab"}}'
            if(($label -join '').Trim() -ne 'synthetic'){throw 'Source volume is not synthetic.'}
            $sources[$case.case]=@{volume=$case.source_volume;root=Join-Path $resolved $case.case}
        }
    }
}
foreach($mode in $modes){if(!$sources.ContainsKey($mode)){throw "Missing passed native matrix case: $mode"}}
$suffix=$Suite+'-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$labRoot=Join-Path $allowedRoot $suffix
$resource='cm-backup-lab-'+$suffix
$image='sha256:7791889374e752a470ed491c5c7684bf91d64c2472721539bef3a64f5276e074'
$helper='sha256:e2eff0ff74b146b126cc88f05f0ee7f863c40041de2849d6c304bd40fe0ce496'
$active=[Collections.Generic.List[string]]::new()
$saved=@{};foreach($key in @('GOOS','GOARCH','CGO_ENABLED','GOPROXY','GOSUMDB','GOTOOLCHAIN')){$saved[$key]=[Environment]::GetEnvironmentVariable($key,'Process')}
$location=Get-Location
function Start-MixedMySQL([string]$role,[string]$init,[string]$query,[string]$expected){
    $name=$resource+'-'+$role
    Invoke-MixedDocker run -d --pull never --name $name --label 'clawmanager.backup-lab=synthetic' --network $resource --network-alias mysql --memory 1g --env MYSQL_ROOT_PASSWORD_FILE=/lab-creds/mysql-root --mount "type=volume,source=$name,target=/var/lib/mysql" --mount "type=bind,source=$labRoot/credentials,target=/lab-creds,readonly" --mount "type=bind,source=$labRoot/tls,target=/lab-tls,readonly" --mount "type=bind,source=$labRoot/$init,target=/docker-entrypoint-initdb.d,readonly" $image --ssl-ca=/lab-tls/ca.pem --ssl-cert=/lab-tls/server.pem --ssl-key=/lab-tls/server-key.pem --require-secure-transport=ON --partial-revokes=ON --innodb-buffer-pool-size=64M | Out-Null
    $active.Add($name)
    Invoke-MixedDocker exec --user 0:0 $name sh -c 'umask 077; cp /lab-creds/root.cnf /tmp/lab-root.cnf; chmod 600 /tmp/lab-root.cnf'
    $ready=$false
    for($i=0;$i -lt 45;$i++){
        $r=& docker --context desktop-linux exec $name mysql --defaults-extra-file=/tmp/lab-root.cnf --batch --skip-column-names -e $query 2>&1
        if($LASTEXITCODE -eq 0 -and ($r -join '').Trim() -eq $expected){$ready=$true;break}
        Start-Sleep -Seconds 2
    }
    if(!$ready){throw "Synthetic $role MySQL did not initialize."}
}
function Stop-MixedMySQL([string]$role){
    $name=$resource+'-'+$role
    Invoke-MixedDocker stop --time 20 $name | Out-Null
    $state=Invoke-MixedDocker inspect $name --format '{{.State.Running}}'
    if(($state -join '').Trim() -ne 'false'){throw 'Database not stopped.'}
    $active.Remove($name) | Out-Null
}
try {
    Set-Location (Join-Path $repo 'backend')
    $env:GOTOOLCHAIN='local';$env:GOPROXY='off';$env:GOSUMDB='off';$env:GOOS='windows';$env:GOARCH='amd64'
    & go run ./cmd/backup-lab --action prepare --suite $Suite --root $labRoot
    if($LASTEXITCODE -ne 0){throw 'Mixed fixture preparation failed.'}
    $env:GOOS='linux';$env:CGO_ENABLED='0'
    & go build -trimpath -o (Join-Path $labRoot 'bin/backup-lab') ./cmd/backup-lab
    if($LASTEXITCODE -ne 0){throw 'Mixed runner build failed.'}
    $id=(Get-Content -LiteralPath (Join-Path $labRoot 'credentials/lab.json') -Raw | ConvertFrom-Json).ID
    $matrixCases=@(foreach($mode in $modes){Get-Content -LiteralPath (Join-Path $sources[$mode].root 'case.json') -Raw | ConvertFrom-Json})
    $matrixCases | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $labRoot 'matrix-cases.json') -Encoding utf8NoBOM
    if($Suite -eq 'workbuddy-identity'){Copy-Item -LiteralPath (Join-Path $sources['workbuddy-lite'].root 'case.json') -Destination (Join-Path $labRoot 'case.json')}
    @{root=$labRoot;id=$id;network=$resource;sources=$sources;scope=$modes;users=4;instances=$instanceCount;suite=$Suite;excluded=@('codex-pro','claude-code-pro');kubernetes_verified=$false} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $labRoot 'environment.json') -Encoding utf8NoBOM
    Invoke-MixedDocker network create --internal --label 'clawmanager.backup-lab=synthetic' $resource | Out-Null
    foreach($part in @('source','target','source-files','restored')){Invoke-MixedDocker volume create --label 'clawmanager.backup-lab=synthetic' ($resource+'-'+$part) | Out-Null}
    foreach($mode in $modes){
        $v=$sources[$mode].volume
        # Positional arguments, not source-derived shell command text.
        if($Suite -eq 'workbuddy-identity'){
            Invoke-MixedDocker run --rm --pull never --network none --mount "type=volume,source=$v,target=/one,readonly" --mount "type=volume,source=$resource-source-files,target=/source" --entrypoint sh $image -c 'mkdir -p /source/workbuddy-a/home /source/workbuddy-b/home && cp -a /one/. /source/workbuddy-a/home/ && cp -a /one/. /source/workbuddy-b/home/'
        } else {
            Invoke-MixedDocker run --rm --pull never --network none --mount "type=volume,source=$v,target=/one,readonly" --mount "type=volume,source=$resource-source-files,target=/source" --entrypoint sh $image -c 'mkdir /source/"$1" && cp -a /one/. /source/"$1"/' copy $mode
        }
    }
    if($Suite -eq 'workbuddy-identity'){
        $identityFixture=Join-Path $PSScriptRoot 'workbuddy-identity-fixtures.py'
        Invoke-MixedDocker run --rm --pull never --network none --read-only --mount "type=volume,source=$resource-source-files,target=/source" --mount "type=bind,source=$labRoot,target=/lab" --mount "type=bind,source=$identityFixture,target=/fixture.py,readonly" --entrypoint python3 $helper /fixture.py seed
    }
    Start-MixedMySQL 'source' 'init' 'SELECT IF(@@GLOBAL.skip_networking=0,COUNT(*),-1) FROM cm_source_backup_lab.instances' ([string]$instanceCount)
    $sourceUUID=Invoke-MixedDocker exec ($resource+'-source') mysql --defaults-extra-file=/tmp/lab-root.cnf --batch --skip-column-names -e 'SELECT @@server_uuid'
    Invoke-MixedDocker exec ($resource+'-source') mysql --defaults-extra-file=/tmp/lab-root.cnf -e 'SET GLOBAL read_only=ON; SET GLOBAL super_read_only=ON;'
    Invoke-MixedDocker run --rm --pull never --network $resource --read-only --memory 1g --mount "type=volume,source=$resource-source-files,target=/source,readonly" --mount "type=bind,source=$labRoot,target=/lab" --mount "type=bind,source=$labRoot/credentials,target=/lab/credentials,readonly" --entrypoint /lab/bin/backup-lab $image --action capture --root /lab
    Stop-MixedMySQL 'source'
    Start-MixedMySQL 'target' 'target-init' 'SELECT IF(@@GLOBAL.skip_networking=0,COUNT(*),-1) FROM cm_drill_backup_lab.users' '1'
    $targetUUID=Invoke-MixedDocker exec ($resource+'-target') mysql --defaults-extra-file=/tmp/lab-root.cnf --batch --skip-column-names -e 'SELECT @@server_uuid'
    @{ID=$id;SourceUUID=($sourceUUID -join '').Trim();TargetUUID=($targetUUID -join '').Trim()} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'target-identity.json') -Encoding utf8NoBOM
    $verify=Join-Path $labRoot 'verifier';New-Item -ItemType Directory -Path $verify | Out-Null
    $inputs=@('--mount',"type=bind,source=$labRoot/bin,target=/lab/bin,readonly",'--mount',"type=bind,source=$labRoot/artifacts,target=/lab/artifacts,readonly",'--mount',"type=bind,source=$labRoot/expected.json,target=/lab/expected.json,readonly",'--mount',"type=bind,source=$labRoot/target-identity.json,target=/lab/target-identity.json,readonly",'--mount',"type=bind,source=$labRoot/tls,target=/lab/tls,readonly")
    $inputs+=@('--mount',"type=bind,source=$labRoot/matrix-cases.json,target=/lab/matrix-cases.json,readonly")
    $restoreAction='mixed-restore';$verifyAction='mixed-verify'
    if($Suite -eq 'workbuddy-identity'){
        $restoreAction='identity-restore';$verifyAction='identity-verify'
        $inputs+=@('--mount',"type=bind,source=$labRoot/case.json,target=/lab/case.json,readonly")
    }
    Invoke-MixedDocker run --rm --pull never --network $resource --read-only --memory 1g --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --mount "type=volume,source=$resource-restored,target=/restored" --mount "type=bind,source=$verify,target=/lab" --mount "type=bind,source=$labRoot/credentials,target=/lab/credentials,readonly" @inputs --entrypoint /lab/bin/backup-lab $image --action $restoreAction --root /lab
    Invoke-MixedDocker exec ($resource+'-target') mysql --defaults-extra-file=/tmp/lab-root.cnf -e "ALTER USER 'lab_restore'@'%' ACCOUNT LOCK; REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'lab_restore'@'%'; SET GLOBAL read_only=ON; SET GLOBAL super_read_only=ON;"
    Invoke-MixedDocker run --rm --pull never --network $resource --read-only --memory 1g --cap-drop ALL --cap-add DAC_OVERRIDE --mount "type=volume,source=$resource-restored,target=/restored,readonly" --mount "type=bind,source=$verify,target=/lab" --mount "type=bind,source=$labRoot/verify-credentials,target=/lab/credentials,readonly" @inputs --entrypoint /lab/bin/backup-lab $image --action $verifyAction --root /lab
    Stop-MixedMySQL 'target'
    # Cross-instance isolation using actual restored Linux owners. No Agent starts.
    $fixture=Join-Path $PSScriptRoot 'mixed-agent-verify.py'
    if($Suite -eq 'workbuddy-identity'){
        Invoke-MixedDocker run --rm --pull never --network none --read-only --tmpfs '/tmp:rw,size=128m' --mount "type=volume,source=$resource-restored,target=/restored,readonly" --mount "type=bind,source=$verify,target=/lab" --mount "type=bind,source=$labRoot/identity-inventory.json,target=/lab/identity-inventory.json,readonly" --mount "type=bind,source=$identityFixture,target=/fixture.py,readonly" --entrypoint python3 $helper /fixture.py verify
    } else {
        Invoke-MixedDocker run --rm --pull never --network none --read-only --tmpfs '/tmp:rw,size=128m' --mount "type=volume,source=$resource-restored,target=/restored,readonly" --mount "type=bind,source=$verify,target=/lab" --mount "type=bind,source=$fixture,target=/fixture.py,readonly" --entrypoint python3 $helper /fixture.py
    }
    foreach($file in @('mixed-restore-result.json','mixed-verify-result.json','mixed-linux-result.json')){Copy-Item -LiteralPath (Join-Path $verify $file) -Destination $labRoot}
    Write-Output "Mixed isolated SQL and workspace drill passed: $labRoot"
} finally {
    foreach($name in $active){& docker --context desktop-linux stop --time 20 $name | Out-Null}
    Set-Location $location
    foreach($key in $saved.Keys){[Environment]::SetEnvironmentVariable($key,$saved[$key],'Process')}
}
