param(
    [Parameter(Mandatory=$true)][string]$LogPath,
    [switch]$Native,
    [string]$CredentialsFile
)
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$backendRoot = Join-Path $repoRoot 'backend'
if ($Native -and (-not $CredentialsFile -or -not (Test-Path -LiteralPath $CredentialsFile -PathType Leaf))) {
    throw 'Native requires the original owner-provisioned SAN/TLS fixture credential file. Never use production credentials.'
}
if ($Native) { $CredentialsFile = [IO.Path]::GetFullPath($CredentialsFile) }
$logTarget = [IO.Path]::GetFullPath($LogPath)
if (Test-Path -LiteralPath $logTarget) { throw 'Refusing to overwrite an existing log.' }
$taskBuild = Join-Path $backendRoot ('.a-permit-validation-' + [guid]::NewGuid().ToString('N'))
$environmentNames = @('GOMAXPROCS','GOTELEMETRY','GOTOOLCHAIN','GOPROXY','GOCACHE','GOTMPDIR','TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS')
$previous = @{}
foreach ($name in $environmentNames) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$testExit = 1
Push-Location $backendRoot
try {
    New-Item -ItemType Directory -Path $taskBuild,(Join-Path $taskBuild 'cache'),(Join-Path $taskBuild 'tmp') | Out-Null
    $env:GOMAXPROCS='2'; $env:GOTELEMETRY='off'; $env:GOTOOLCHAIN='local'; $env:GOPROXY='off'
    $env:GOCACHE=Join-Path $taskBuild 'cache'
    $env:GOTMPDIR=Join-Path $taskBuild 'tmp'
    if ($Native) {
        # Apply the reviewed native context patch before this run. The fixture
        # may retain FAILED SQL namespaces for owner review; this script never
        # drops a database or rewrites an original task/window.
        $env:TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS=[IO.Path]::GetFullPath($CredentialsFile)
        & go test -count=1 -p=2 -timeout=15m -v ./internal/systembackupexecution -run '^TestDOriginalUploadedManifestMarkerAndCandidateCleanupMySQL$' 2>&1 | Tee-Object -FilePath $logTarget
    } else {
        & go test -count=1 -p=2 -timeout=10m -v ./internal/systembackupkekadapter -run '^TestProviderPermitTiming' 2>&1 | Tee-Object -FilePath $logTarget
    }
    $testExit=$LASTEXITCODE
    if ($Native -and $testExit -eq 0) {
        if ((Select-String -LiteralPath $logTarget -Pattern '^\s*--- SKIP:' -Quiet) -or -not (Select-String -LiteralPath $logTarget -SimpleMatch 'provider-permit-stage-timing DATA' -Quiet)) {
            throw 'Native run skipped or missing the actual context-chain timing output.'
        }
    }
} finally {
    Pop-Location
    foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
    $resolvedBuild = [IO.Path]::GetFullPath($taskBuild)
    if (-not $resolvedBuild.StartsWith($backendRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup target outside backend.' }
    if (Test-Path -LiteralPath $resolvedBuild) { Remove-Item -LiteralPath $resolvedBuild -Recurse -Force }
}
exit $testExit
