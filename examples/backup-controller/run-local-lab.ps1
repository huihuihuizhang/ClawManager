# Creates only uniquely named synthetic Docker resources. Never uses kubeconfig,
# remote Docker contexts, existing databases, production credentials or registries.
param([switch]$SkipOpenClawStart)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$backend = Join-Path $repo 'backend'
$suffix = 'run-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$labRoot = Join-Path $repo ('.codex-temp/backup-lab/' + $suffix)
$resource = 'cm-backup-lab-' + $suffix
$mysqlImage = 'sha256:7791889374e752a470ed491c5c7684bf91d64c2472721539bef3a64f5276e074'
$agentImages = @{
    lite='sha256:14338738e779f86f239c1a6787ccfe5b56a619f86130033f86aecfff9169d921'
    pro='sha256:0c1fd9ee598b536098c57a745b87fd5bbbeb6ab7b2cfed128cf0d7fc3b392590'
}
function Invoke-LabDocker {
    & docker --context desktop-linux @args
    if ($LASTEXITCODE -ne 0) { throw 'Local isolated Docker operation failed; resources retained for inspection.' }
}
$dockerEndpoint = (& docker context inspect desktop-linux --format '{{.Endpoints.docker.Host}}').Trim()
if ($LASTEXITCODE -ne 0 -or $dockerEndpoint -ne 'npipe:////./pipe/dockerDesktopLinuxEngine') { throw 'Expected local Docker Desktop Linux engine.' }
foreach ($image in @($mysqlImage) + @($agentImages.Values)) { Invoke-LabDocker image inspect $image --format '{{.Id}}' }
$previousLocation = Get-Location
$oldGoos = $env:GOOS; $oldGoarch = $env:GOARCH; $oldCgo = $env:CGO_ENABLED
$oldProxy = $env:GOPROXY; $oldSum = $env:GOSUMDB; $oldToolchain=$env:GOTOOLCHAIN
$createdDatabase = $false
$activeAgents = [Collections.Generic.List[string]]::new()
try {
    Set-Location $backend
    $env:GOTOOLCHAIN='local'; $env:GOPROXY='off'; $env:GOSUMDB='off'
    $env:GOOS='windows'; $env:GOARCH='amd64'
    & go run ./cmd/backup-lab --action prepare --root $labRoot
    if ($LASTEXITCODE -ne 0) { throw 'Lab preparation failed.' }
    $env:GOOS='linux'; $env:CGO_ENABLED='0'
    & go build -trimpath -o (Join-Path $labRoot 'bin/backup-lab') ./cmd/backup-lab
    if ($LASTEXITCODE -ne 0) { throw 'Linux lab runner build failed.' }
    $manifest = [ordered]@{schema='isolated-backup-lab.v1';root=$labRoot;docker_context='desktop-linux';network=$resource;database=$resource+'-mysql';volume=$resource+'-mysql';images=$agentImages;mysql_image=$mysqlImage;agents=@{};kubernetes_controller_verified=$false;runtime_agent_lifecycle_verified=$false}
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $labRoot 'environment.json') -Encoding utf8
    foreach ($mode in @('lite','pro')) {
        $source = Join-Path $labRoot ('source/'+$mode)
        Invoke-LabDocker run --rm --pull never --network none --user 0:0 --read-only --tmpfs '/tmp:rw,size=128m' --env OPENCLAW_STATE_DIR=/state --env OPENCLAW_CONFIG_PATH=/state/openclaw.json --mount "type=bind,source=$source,target=/state" --entrypoint /usr/local/bin/openclaw $agentImages[$mode] setup --baseline --workspace /state/workspace
        if (!(Test-Path -LiteralPath (Join-Path $source 'openclaw.json'))) { throw 'OpenClaw did not create the isolated config.' }
        $version = Invoke-LabDocker run --rm --pull never --network none --read-only --tmpfs '/tmp:rw,size=64m' --entrypoint /usr/local/bin/openclaw $agentImages[$mode] --version
        $manifest.agents[$mode] = @{version=($version -join "`n");baseline_created=$true;gateway_health_verified=$false;stopped=$false}
        if (!$SkipOpenClawStart) {
            $agentName = $resource+'-'+$mode
            Invoke-LabDocker run -d --name $agentName --label 'clawmanager.backup-lab=synthetic' --pull never --network none --user 0:0 --read-only --tmpfs '/tmp:rw,size=256m' --memory 1g --env OPENCLAW_STATE_DIR=/state --env OPENCLAW_CONFIG_PATH=/state/openclaw.json --env OPENCLAW_GATEWAY_TOKEN=synthetic-lab-token-only --mount "type=bind,source=$source,target=/state" --entrypoint /usr/local/bin/openclaw $agentImages[$mode] gateway run --allow-unconfigured --auth token --bind loopback --port 18789
            $activeAgents.Add($agentName)
            $healthy=$false
            for($i=0;$i -lt 15;$i++) {
                $health = & docker --context desktop-linux exec $agentName /usr/local/bin/openclaw gateway health --json 2>&1
                if($LASTEXITCODE -eq 0){ $healthy=$true; break }
                Start-Sleep -Seconds 2
            }
            if(!$healthy){throw "Isolated OpenClaw $mode health check failed."}
            Invoke-LabDocker stop --time 20 $agentName
            $state=(& docker --context desktop-linux inspect $agentName --format '{{.State.Running}}').Trim()
            if($LASTEXITCODE -ne 0 -or $state -ne 'false'){throw 'Agent not confirmed stopped.'}
            $activeAgents.Remove($agentName) | Out-Null
            $manifest.agents[$mode].gateway_health_verified=$true
            $manifest.agents[$mode].stopped=$true
        }
        $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $labRoot 'environment.json') -Encoding utf8
    }
    Invoke-LabDocker network create --internal --label 'clawmanager.backup-lab=synthetic' $resource
    Invoke-LabDocker volume create --label 'clawmanager.backup-lab=synthetic' ($resource+'-mysql')
    Invoke-LabDocker run -d --pull never --name ($resource+'-mysql') --label 'clawmanager.backup-lab=synthetic' --network $resource --network-alias mysql --memory 1g --env MYSQL_ROOT_PASSWORD_FILE=/lab-creds/mysql-root --mount "type=volume,source=$resource-mysql,target=/var/lib/mysql" --mount "type=bind,source=$labRoot/credentials,target=/lab-creds,readonly" --mount "type=bind,source=$labRoot/tls,target=/lab-tls,readonly" --mount "type=bind,source=$labRoot/init,target=/docker-entrypoint-initdb.d,readonly" $mysqlImage --ssl-ca=/lab-tls/ca.pem --ssl-cert=/lab-tls/server.pem --ssl-key=/lab-tls/server-key.pem --require-secure-transport=ON --partial-revokes=ON --innodb-buffer-pool-size=64M
    $createdDatabase=$true
    # Docker Desktop bind mounts have permissive Unix modes; MySQL ignores such
    # option files. Copy only this generated lab credential into container tmp.
    Invoke-LabDocker exec --user 0:0 ($resource+'-mysql') /bin/sh -c 'umask 077; cp /lab-creds/root.cnf /tmp/lab-root.cnf; chmod 600 /tmp/lab-root.cnf'
    $ready=$false
    for($i=0;$i -lt 40;$i++) {
        $check = & docker --context desktop-linux exec ($resource+'-mysql') mysql --defaults-extra-file=/tmp/lab-root.cnf --batch --skip-column-names -e 'SELECT IF(@@GLOBAL.skip_networking=0,COUNT(*),-1) FROM cm_source_backup_lab.instances' 2>&1
        if($LASTEXITCODE -eq 0 -and ($check -join '').Trim() -eq '2'){$ready=$true;break}
        Start-Sleep -Seconds 2
    }
    if(!$ready){throw 'Isolated MySQL initialization failed.'}
    Invoke-LabDocker exec ($resource+'-mysql') mysql --defaults-extra-file=/tmp/lab-root.cnf -e 'SET GLOBAL read_only=ON; SET GLOBAL super_read_only=ON;'
    Invoke-LabDocker run --rm --pull never --network $resource --read-only --tmpfs '/tmp:rw,size=64m' --mount "type=bind,source=$labRoot,target=/lab" --mount "type=bind,source=$labRoot/source,target=/lab/source,readonly" --mount "type=bind,source=$labRoot/source,target=/source,readonly" --mount "type=bind,source=$labRoot/credentials,target=/lab/credentials,readonly" --entrypoint /lab/bin/backup-lab $mysqlImage --action capture --root /lab
    Invoke-LabDocker stop --time 20 ($resource+'-mysql')
    $createdDatabase=$false
    $dbState=(& docker --context desktop-linux inspect ($resource+'-mysql') --format '{{.State.Running}}').Trim()
    if($LASTEXITCODE -ne 0 -or $dbState -ne 'false'){throw 'Source database not confirmed stopped.'}
    $verifyRoot=Join-Path $labRoot 'verifier'
    New-Item -ItemType Directory -Path $verifyRoot | Out-Null
    # Give the offline verifier no source workspace, SQL, initialization files or
    # staging mount. Its only inputs are the published package, keys and MACs.
    Invoke-LabDocker run --rm --pull never --network none --read-only --tmpfs '/tmp:rw,size=64m' --mount "type=bind,source=$verifyRoot,target=/lab" --mount "type=bind,source=$labRoot/bin,target=/lab/bin,readonly" --mount "type=bind,source=$labRoot/credentials,target=/lab/credentials,readonly" --mount "type=bind,source=$labRoot/artifacts,target=/lab/artifacts,readonly" --mount "type=bind,source=$labRoot/expected.json,target=/lab/expected.json,readonly" --mount "type=bind,source=$labRoot/verification,target=/lab/verification" --entrypoint /lab/bin/backup-lab $mysqlImage --action verify --root /lab
    Copy-Item -LiteralPath (Join-Path $verifyRoot 'result.json') -Destination (Join-Path $labRoot 'result.json')
    Write-Output "Lab report: $labRoot/result.json"
} finally {
    foreach($name in $activeAgents){ & docker --context desktop-linux stop --time 20 $name | Out-Null }
    if($createdDatabase){ & docker --context desktop-linux stop --time 20 ($resource+'-mysql') | Out-Null }
    Set-Location $previousLocation
    $env:GOOS=$oldGoos; $env:GOARCH=$oldGoarch; $env:CGO_ENABLED=$oldCgo
    $env:GOPROXY=$oldProxy; $env:GOSUMDB=$oldSum; $env:GOTOOLCHAIN=$oldToolchain
}
