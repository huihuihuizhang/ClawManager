param(
    [Parameter(Mandatory=$true)][string]$LogPath,
    [switch]$Native,
    [string]$CredentialsFile,
    [string]$DisposableServerUUID,
    [string]$BuildRoot
)
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$backendRoot = Join-Path $repoRoot 'backend'
$null = Get-Command go -CommandType Application -ErrorAction Stop
if ($Native) {
    if (-not $CredentialsFile -or -not (Test-Path -LiteralPath $CredentialsFile -PathType Leaf)) { throw 'Native requires private disposable SAN/TLS credentials; never production.' }
    if ($DisposableServerUUID -cnotmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') { throw 'Native requires an independent DisposableServerUUID pin.' }
    $CredentialsFile = [IO.Path]::GetFullPath($CredentialsFile)
    $hook = Get-Content -LiteralPath (Join-Path $backendRoot 'internal/systembackupexecution/production_same_task_mysql_test.go') -Raw
    if (-not $hook.Contains('WithProviderPermitTiming') -or -not $hook.Contains('provider-permit-stage-timing DATA')) { throw 'Actual original native context hook is missing; no manual patch step is supported.' }
    $sourceCommit = (& git -C $repoRoot rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or $sourceCommit -cnotmatch '^[a-f0-9]{40}$') { throw 'A real source commit is required for the original linked capture identity.' }
}
$logTarget = [IO.Path]::GetFullPath($LogPath)
if (Test-Path -LiteralPath $logTarget) { throw 'Refusing to overwrite an existing log.' }
if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($logTarget)) -PathType Container)) { throw 'Log parent directory must already exist.' }
if (-not $BuildRoot) { $BuildRoot = $backendRoot }
$buildParent = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $BuildRoot).Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
$driveRoot = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath((Resolve-Path -LiteralPath $BuildRoot).Path))
if ($buildParent -ceq $driveRoot.TrimEnd([IO.Path]::DirectorySeparatorChar)) { $buildParent = $driveRoot }
if (-not (Test-Path -LiteralPath $buildParent -PathType Container) -or ((Get-Item -LiteralPath $buildParent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'BuildRoot must be an existing nonredirected directory.' }
$buildID = [guid]::NewGuid().ToString('N')
$taskBuild = Join-Path $buildParent ('.a-permit-validation-' + $buildID)
$environmentNames = @('GOMAXPROCS','GOTELEMETRY','GOTOOLCHAIN','GOPROXY','GOCACHE','GOTMPDIR','TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS','A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID')
$previous = @{}
foreach ($name in $environmentNames) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$testExit = 1
$buildCreated = $false
$cleanupFailed = $false
$runFailure = $null
Push-Location $backendRoot
try {
    # No -Force: a pre-existing directory is never adopted or cleaned.
    New-Item -ItemType Directory -Path $taskBuild | Out-Null
    $buildCreated = $true
    [IO.File]::WriteAllText((Join-Path $taskBuild '.owner'), $buildID)
    New-Item -ItemType Directory -Path (Join-Path $taskBuild 'cache'),(Join-Path $taskBuild 'tmp') | Out-Null
    $env:GOMAXPROCS='2'; $env:GOTELEMETRY='off'; $env:GOTOOLCHAIN='local'; $env:GOPROXY='off'
    $env:GOCACHE=Join-Path $taskBuild 'cache'
    $env:GOTMPDIR=Join-Path $taskBuild 'tmp'
    if ($Native) {
        $env:TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS=$CredentialsFile
        $env:A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID=$DisposableServerUUID
        $goArguments = @('test','-count=1','-p=2','-timeout=15m','-v','-ldflags',('-X clawreef/internal/buildinfo.Commit='+$sourceCommit),'./internal/systembackupexecution','-run','^TestAPermitTimingOriginalThirtySecondNativeMySQL$')
    } else {
        $goArguments = @('test','-count=1','-p=2','-timeout=10m','-v','./internal/systembackupkekadapter','-run','^TestProviderPermitTiming')
    }
    $teeErrors = @()
    try {
        # Preserve the go exit code even when PS5 represents stderr as errors.
        $ErrorActionPreference='Continue'
        & go @goArguments 2>&1 | Tee-Object -FilePath $logTarget -ErrorAction SilentlyContinue -ErrorVariable +teeErrors
        $testExit=$LASTEXITCODE
    } finally { $ErrorActionPreference='Stop' }
    if ($teeErrors.Count -gt 0) { throw 'Diagnostic log write failed.' }
    if ($Native -and $testExit -eq 0) {
        if ((Select-String -LiteralPath $logTarget -Pattern '^\s*--- SKIP:' -Quiet) -or -not (Select-String -LiteralPath $logTarget -SimpleMatch 'provider-permit-stage-timing DATA' -Quiet) -or -not (Select-String -LiteralPath $logTarget -SimpleMatch '--- PASS: TestAPermitTimingOriginalThirtySecondNativeMySQL' -Quiet)) { throw 'Native skipped or missing actual entry PASS/context-chain timing output.' }
    }
} catch {
    $runFailure = $_
} finally {
    Pop-Location
    foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
    if ($buildCreated) {
        try {
            $resolvedBuild = [IO.Path]::GetFullPath($taskBuild)
            if ([IO.Path]::GetDirectoryName($resolvedBuild) -cne $buildParent -or [IO.Path]::GetFileName($resolvedBuild) -cne ('.a-permit-validation-'+$buildID)) { throw 'Cleanup exact parent/name mismatch.' }
            if (Test-Path -LiteralPath $resolvedBuild) {
                if ((Get-Item -LiteralPath $resolvedBuild -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected build directory; cleanup refused.' }
                if ([IO.File]::ReadAllText((Join-Path $resolvedBuild '.owner')) -cne $buildID) { throw 'Build owner marker mismatch; cleanup refused.' }
                Remove-Item -LiteralPath $resolvedBuild -Recurse -Force
            }
            if (Test-Path -LiteralPath $resolvedBuild) { throw 'Own build directory remains.' }
        } catch {
            $cleanupFailed = $true
            Write-Warning ('Own build cleanup incomplete: '+$taskBuild+'; '+$_.Exception.Message)
        }
    }
}
if ($runFailure) { Write-Error $runFailure -ErrorAction Continue }
if ($testExit -ne 0) { exit $testExit }
if ($runFailure -or $cleanupFailed) { exit 1 }
exit 0
