# Reproducible Wine layout round trip, using only new Linux Docker volumes.
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$fixture=Join-Path $PSScriptRoot 'workbuddy-lab-fixtures.py'
$suffix='wine-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$labRoot=Join-Path $repo ('.codex-temp/backup-lab/'+$suffix)
$resource='cm-backup-lab-'+$suffix
$image='sha256:e2eff0ff74b146b126cc88f05f0ee7f863c40041de2849d6c304bd40fe0ce496'
function Invoke-WineDocker {
    & docker --context desktop-linux @args
    if($LASTEXITCODE -ne 0){throw 'Isolated Wine lab failed; generated artifacts and volumes retained.'}
}
$endpoint=(& docker context inspect desktop-linux --format '{{.Endpoints.docker.Host}}').Trim()
if($LASTEXITCODE -ne 0 -or $endpoint -ne 'npipe:////./pipe/dockerDesktopLinuxEngine'){throw 'Expected local Docker Desktop Linux engine.'}
Invoke-WineDocker image inspect $image --format '{{.Id}}'
$digest=Invoke-WineDocker image inspect $image --format '{{json .RepoDigests}}'
if(($digest -join '') -notmatch 'sha256:5d5aa912f211949e0e3a52884533b8c9685697890d629ce93868b8fdf5acde71'){throw 'Wine policy image digest mismatch.'}
$location=Get-Location
$savedEnv=@{}
foreach($key in @('GOOS','GOARCH','CGO_ENABLED','GOPROXY','GOSUMDB','GOTOOLCHAIN')){$savedEnv[$key]=[Environment]::GetEnvironmentVariable($key,'Process')}
try {
    Set-Location (Join-Path $repo 'backend')
    $env:GOTOOLCHAIN='local';$env:GOPROXY='off';$env:GOSUMDB='off';$env:GOOS='windows';$env:GOARCH='amd64'
    & go run ./cmd/backup-lab --action prepare --suite workbuddy --root $labRoot
    if($LASTEXITCODE -ne 0){throw 'Lab preparation failed.'}
    $env:GOOS='linux';$env:CGO_ENABLED='0'
    & go build -trimpath -o (Join-Path $labRoot 'bin/backup-lab') ./cmd/backup-lab
    if($LASTEXITCODE -ne 0){throw 'Lab runner build failed.'}
    $kernel=Invoke-WineDocker info --format '{{.KernelVersion}}'
    @{schema='workbuddy-wine-lab.v1';root=$labRoot;host='Windows';runtime='Linux containers';kernel=($kernel -join '');image=$image;source_volume=$resource+'-source';target_volume=$resource+'-target';storage='Linux named volumes';workspace_layout='workbuddy-lite-wine.v1';network='none';kubernetes_verified=$false;server_verified=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'environment.json') -Encoding utf8
    foreach($volume in @('source','target')){Invoke-WineDocker volume create --label 'clawmanager.backup-lab=synthetic' ($resource+'-'+$volume)}
    Invoke-WineDocker run --rm --pull never --network none --read-only --mount "type=volume,source=$resource-source,target=/source" --entrypoint python3 $image -c 'import os; os.chown("/source",12001,12001); os.chmod("/source",0o700)'
    Invoke-WineDocker run --rm --pull never --network none --read-only --user 12001:12001 --cap-drop ALL --security-opt no-new-privileges --memory 2g --pids-limit 256 --tmpfs '/tmp:rw,size=128m,mode=1777' --mount "type=volume,source=$resource-source,target=/source" --mount "type=bind,source=$labRoot,target=/lab" --mount "type=bind,source=$fixture,target=/fixture.py,readonly" --entrypoint python3 $image /fixture.py wine-prepare
    Invoke-WineDocker run --rm --pull never --network none --read-only --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --memory 1g --mount "type=volume,source=$resource-source,target=/source,readonly" --mount "type=bind,source=$labRoot,target=/lab" --mount "type=bind,source=$labRoot/credentials,target=/lab/credentials,readonly" --entrypoint /lab/bin/backup-lab $image --action capture-workbuddy-wine --root /lab
    $verifyRoot=Join-Path $labRoot 'verifier'
    New-Item -ItemType Directory -Path $verifyRoot | Out-Null
    # Restore receives only the signed capture metadata, keys and ciphertext.
    # The source volume is not attached, and the container has no network.
    Invoke-WineDocker run --rm --pull never --network none --read-only --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --memory 1g --mount "type=volume,source=$resource-target,target=/target" --mount "type=bind,source=$verifyRoot,target=/lab" --mount "type=bind,source=$labRoot/bin,target=/lab/bin,readonly" --mount "type=bind,source=$labRoot/credentials,target=/lab/credentials,readonly" --mount "type=bind,source=$labRoot/wine-staging,target=/lab/wine-staging,readonly" --mount "type=bind,source=$labRoot/wine-capture.json,target=/lab/wine-capture.json,readonly" --entrypoint /lab/bin/backup-lab $image --action restore-workbuddy-wine --root /lab
    Invoke-WineDocker run --rm --pull never --network none --read-only --tmpfs '/tmp:rw,size=128m' --mount "type=volume,source=$resource-target,target=/target,readonly" --mount "type=bind,source=$verifyRoot,target=/lab" --mount "type=bind,source=$labRoot/wine-inventory.json,target=/lab/wine-inventory.json,readonly" --mount "type=bind,source=$fixture,target=/fixture.py,readonly" --entrypoint python3 $image /fixture.py wine-compare
    # Start only Wine CLI in the restored test prefix, not a user Agent. Verify
    # persisted registry/documents and stop all Wine processes afterwards.
    Invoke-WineDocker run --rm --pull never --network none --read-only --user 12001:12001 --cap-drop ALL --security-opt no-new-privileges --memory 2g --pids-limit 256 --tmpfs '/tmp:rw,size=128m,mode=1777' --mount "type=volume,source=$resource-target,target=/source/workbuddy-wine" --mount "type=bind,source=$verifyRoot,target=/lab" --mount "type=bind,source=$fixture,target=/fixture.py,readonly" --entrypoint python3 $image /fixture.py wine-smoke
    foreach($name in @('workbuddy-wine-result.json','wine-metadata-result.json','wine-runtime-result.json')){Copy-Item -LiteralPath (Join-Path $verifyRoot $name) -Destination (Join-Path $labRoot $name)}
    Write-Output "Wine layout round trip passed: $labRoot"
    Write-Output 'Identity table migration, native editor editing and Linux/K8s server acceptance remain unverified.'
} finally {
    Set-Location $location
    foreach($key in $savedEnv.Keys){[Environment]::SetEnvironmentVariable($key,$savedEnv[$key],'Process')}
}
