# Cached-image Linux data-plane tests. Each case has fresh source/target volumes.
# Codex Pro and Claude Code Pro are intentionally excluded at the user's request.
param([string[]]$Cases = @())
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$suffix='matrix-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$labRoot=Join-Path $repo ('.codex-temp/backup-lab/'+$suffix)
$resource='cm-backup-lab-'+$suffix
$fixture=Join-Path $PSScriptRoot 'agent-matrix-fixtures.py'
$images=[ordered]@{
    'openclaw-lite'='sha256:14338738e779f86f239c1a6787ccfe5b56a619f86130033f86aecfff9169d921'
    'openclaw-pro'='sha256:0c1fd9ee598b536098c57a745b87fd5bbbeb6ab7b2cfed128cf0d7fc3b392590'
    'hermes-lite'='sha256:2112d6669af4b1425c5aad5c47ad1a472761eec0efeb3476202f8c7d321803d1'
    'hermes-pro'='sha256:85c4d11ac40abd98c0662828c9cd51ad7586baeb79c6f79586a9e6a3cb466f80'
    'opencode-lite'='sha256:5bceaba6178b7d6799673274df849230e64ec31167f5a7815b4a7f22071515f0'
    'opencode-pro'='sha256:5bceaba6178b7d6799673274df849230e64ec31167f5a7815b4a7f22071515f0'
    'deepseek-harness-lite'='sha256:2d4536e0dcd0824e08cf4f3b11e88b9d1bb3916df1f9b3046509777cc7cd40b3'
    'deepseek-harness-pro'='sha256:62cf93cc6b459bf81e9745813a6a306d723991435961bd66afc7b01e39a554d3'
    'workbuddy-lite'='sha256:e2eff0ff74b146b126cc88f05f0ee7f863c40041de2849d6c304bd40fe0ce496'
    'workbuddy-pro'='sha256:cc4a59bd5d58fb309480a24a785eab60e335bb6b129fce9018d453b71ac71c03'
}
function Invoke-MatrixDocker {
    & docker --context desktop-linux @args
    if($LASTEXITCODE -ne 0){throw 'Matrix Docker operation failed; inspect the retained native.log and artifacts.'}
}
$endpoint=(& docker context inspect desktop-linux --format '{{.Endpoints.docker.Host}}').Trim()
if($LASTEXITCODE -ne 0 -or $endpoint -ne 'npipe:////./pipe/dockerDesktopLinuxEngine'){throw 'Expected local Docker Desktop Linux engine.'}
foreach($name in $Cases){if(!$images.Contains($name)){throw "Unknown isolated matrix case: $name"}}
$saved=@{};foreach($key in @('GOOS','GOARCH','CGO_ENABLED','GOPROXY','GOSUMDB','GOTOOLCHAIN')){$saved[$key]=[Environment]::GetEnvironmentVariable($key,'Process')}
$location=Get-Location
$results=[Collections.Generic.List[object]]::new()
try {
    Set-Location (Join-Path $repo 'backend')
    $env:GOTOOLCHAIN='local';$env:GOPROXY='off';$env:GOSUMDB='off';$env:GOOS='windows';$env:GOARCH='amd64'
    & go run ./cmd/backup-lab --action prepare --root $labRoot
    if($LASTEXITCODE -ne 0){throw 'Synthetic lab preparation failed.'}
    Copy-Item -LiteralPath $fixture -Destination (Join-Path $labRoot 'agent-matrix-fixtures.py')
    $fixture=Join-Path $labRoot 'agent-matrix-fixtures.py'
    $env:GOOS='linux';$env:CGO_ENABLED='0'
    & go build -trimpath -o (Join-Path $labRoot 'bin/backup-lab') ./cmd/backup-lab
    if($LASTEXITCODE -ne 0){throw 'Linux runner build failed.'}
    $runnerHash=(Get-FileHash -LiteralPath (Join-Path $labRoot 'bin/backup-lab') -Algorithm SHA256).Hash
    $fixtureHash=(Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
    $index=0
    foreach($name in $images.Keys){
        $index++
        if($Cases.Count -gt 0 -and $name -notin $Cases){continue}
        $caseRoot=Join-Path $labRoot $name
        $image=$images[$name]
        $source=$resource+'-'+$name+'-source';$target=$resource+'-'+$name+'-target'
        $row=[ordered]@{case=$name;status='running';source_volume=$source;target_volume=$target;image_id=$image}
        try {
            $inspection=Invoke-MatrixDocker image inspect $image --format '{{json .RepoDigests}}'
            $digests=@(($inspection -join '') | ConvertFrom-Json)
            if(!$digests -or !$digests[0].Contains('@sha256:')){throw 'Cached image has no immutable repository digest.'}
            $mode=($name -split '-')[-1];$type=$name.Substring(0,$name.Length-$mode.Length-1)
            New-Item -ItemType Directory -Path $caseRoot | Out-Null
            @{Name=$name;Type=$type;Mode=$mode;Image=$digests[0];UID=12100+$index} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $caseRoot 'case.json') -Encoding utf8NoBOM
            Copy-Item -LiteralPath (Join-Path $labRoot 'credentials') -Destination $caseRoot -Recurse
            foreach($volume in @($source,$target)){Invoke-MatrixDocker volume create --label 'clawmanager.backup-lab=synthetic' $volume | Out-Null}
            Write-Output "Native preparation: $name"
            $base=@('run','--rm','--pull','never','--network','none','--read-only','--memory','3g','--pids-limit','512','--tmpfs','/tmp:rw,size=512m,mode=1777','--mount',"type=bind,source=$fixture,target=/fixture.py,readonly")
            Invoke-MatrixDocker @base --mount "type=volume,source=$source,target=/home-lab" --mount "type=volume,source=$source,target=/config" --mount "type=bind,source=$caseRoot,target=/lab" --entrypoint python3 $image /fixture.py prepare
            Invoke-MatrixDocker run --rm --pull never --network none --read-only --memory 1g --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --mount "type=volume,source=$source,target=/source,readonly" --mount "type=bind,source=$caseRoot,target=/lab" --mount "type=bind,source=$labRoot/bin,target=/lab/bin,readonly" --entrypoint /lab/bin/backup-lab $image --action matrix-capture --root /lab
            $verify=Join-Path $caseRoot 'verifier';New-Item -ItemType Directory -Path $verify | Out-Null
            # The restore container sees ciphertext and signed metadata only.
            $inputs=@('--mount',"type=bind,source=$caseRoot/credentials,target=/lab/credentials,readonly",'--mount',"type=bind,source=$caseRoot/case.json,target=/lab/case.json,readonly",'--mount',"type=bind,source=$caseRoot/matrix-capture.json,target=/lab/matrix-capture.json,readonly",'--mount',"type=bind,source=$caseRoot/matrix-staging,target=/lab/matrix-staging,readonly",'--mount',"type=bind,source=$labRoot/bin,target=/lab/bin,readonly")
            Invoke-MatrixDocker run --rm --pull never --network none --read-only --memory 1g --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --mount "type=volume,source=$target,target=/target" --mount "type=bind,source=$verify,target=/lab" @inputs --entrypoint /lab/bin/backup-lab $image --action matrix-restore --root /lab
            foreach($file in @('case.json','inventory.json','native-result.json')){Copy-Item -LiteralPath (Join-Path $caseRoot $file) -Destination $verify}
            Invoke-MatrixDocker @base --mount "type=volume,source=$target,target=/home-lab,readonly" --mount "type=bind,source=$verify,target=/lab" --entrypoint python3 $image /fixture.py compare
            # Native read-back is deliberately separate from immutable byte QA;
            # these are synthetic test instances and all child processes stop.
            Invoke-MatrixDocker @base --mount "type=volume,source=$target,target=/home-lab" --mount "type=volume,source=$target,target=/config" --mount "type=bind,source=$verify,target=/lab" --entrypoint python3 $image /fixture.py native-readback
            $row.status='passed'
        } catch {
            $row.status='failed';$row.error=$_.Exception.Message
            Write-Output "Case failed: $name - $($_.Exception.Message)"
        }
        $results.Add($row)
        @{root=$labRoot;cases=@($results.ToArray());excluded=@('codex-pro','claude-code-pro');network='none';host='Windows Docker Desktop Linux';runner_sha256=$runnerHash;fixture_sha256=$fixtureHash;kubernetes_verified=$false} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $labRoot 'matrix-result.json') -Encoding utf8NoBOM
    }
    Write-Output "Matrix report: $labRoot/matrix-result.json"
    if(@($results | Where-Object status -ne 'passed').Count -gt 0){throw 'Some native matrix cases failed; see per-case logs. No real migration was attempted.'}
} finally {
    Set-Location $location
    foreach($key in $saved.Keys){[Environment]::SetEnvironmentVariable($key,$saved[$key],'Process')}
}
