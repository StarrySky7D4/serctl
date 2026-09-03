[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CliPath,
    [string]$ReceiptPath,
    [ValidatePattern('^v1\.0\.0-beta(?:\.(?:0|[1-9][0-9]*))?$')][string]$Tag,
    [ValidatePattern('^[0-9a-f]{40}$')][string]$TagObject,
    [ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
    [ValidatePattern('^[0-9A-F]{64}$')][string]$ReleaseManifestSha256,
    [string]$EvidenceOwner
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseLogSanitization.ps1')

function Assert-GateCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "Windows multi-account ACL gate failed: $Message"
    }
}

function Assert-SafeReceiptIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-GateCondition (
        -not [string]::IsNullOrWhiteSpace($Value) -and $Value.Length -le 128
    ) "$Label is empty or too long"
    Assert-GateCondition ($Value -notmatch '[\x00-\x1F\x7F]') (
        "$Label contains a control character"
    )
    Assert-GateCondition (
        $Value -notmatch '^[A-Za-z]:[\\/]' -and
        $Value -notmatch '^\\\\' -and
        $Value -notmatch '^/'
    ) "$Label contains an absolute local path"
}

function Add-ReceiptFullControlRule {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSecurity]$Acl,
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$Sid
    )
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $Sid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $Acl.AddAccessRule($rule)
}

function Write-ProtectedCreateNewReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $expectedSha256 = (
            $sha256.ComputeHash($Bytes) |
                ForEach-Object { $_.ToString('x2') }
        ) -join ''
    }
    finally {
        $sha256.Dispose()
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parentPath = [System.IO.Path]::GetDirectoryName($fullPath)
    Assert-GateCondition (-not [string]::IsNullOrWhiteSpace($parentPath)) (
        'receipt destination has no parent directory'
    )
    $parent = Get-Item -LiteralPath $parentPath -Force -ErrorAction Stop
    Assert-GateCondition $parent.PSIsContainer 'receipt parent is not a directory'
    Assert-GateCondition (
        ($parent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) 'receipt parent is a reparse point'
    Assert-GateCondition (-not (Test-Path -LiteralPath $fullPath)) (
        'receipt destination already exists; refusing replacement'
    )

    $stream = [System.IO.FileStream]::new(
        $fullPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)

        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = [System.Security.AccessControl.FileSecurity]::new()
        $acl.SetOwner($currentSid)
        $acl.SetAccessRuleProtection($true, $false)
        Add-ReceiptFullControlRule -Acl $acl -Sid $currentSid
        Add-ReceiptFullControlRule -Acl $acl -Sid (
            [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        )
        Add-ReceiptFullControlRule -Acl $acl -Sid (
            [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        )
        Set-Acl -LiteralPath $fullPath -AclObject $acl -ErrorAction Stop
    }
    catch {
        $stream.Dispose()
        try { Remove-Item -LiteralPath $fullPath -Force -ErrorAction Stop } catch {}
        throw 'protected receipt create-new write failed; diagnostic details withheld'
    }
    finally {
        $stream.Dispose()
    }

    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    Assert-GateCondition (
        -not $item.PSIsContainer -and
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
        $item.Length -eq $Bytes.Length
    ) 'protected receipt post-write identity check failed'
    Assert-GateCondition (
        (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
            $expectedSha256
    ) 'protected receipt bytes do not match the same-process receipt digest'
    $writtenAcl = Get-Acl -LiteralPath $fullPath -ErrorAction Stop
    Assert-GateCondition $writtenAcl.AreAccessRulesProtected (
        'protected receipt DACL still inherits from its parent'
    )
    $writtenOwner = $writtenAcl.GetOwner(
        [System.Security.Principal.SecurityIdentifier]
    )
    Assert-GateCondition ($writtenOwner.Value -ceq $currentSid.Value) (
        'protected receipt owner SID is not the current gate identity'
    )
    $writtenRules = @(
        $writtenAcl.GetAccessRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        )
    )
    $expectedSids = @($currentSid.Value, 'S-1-5-18', 'S-1-5-32-544') |
        Sort-Object -Unique
    $writtenSids = @($writtenRules | ForEach-Object { $_.IdentityReference.Value }) |
        Sort-Object -Unique
    Assert-GateCondition (
        $writtenRules.Count -eq 3 -and
        (($writtenSids -join "`n") -ceq ($expectedSids -join "`n"))
    ) 'protected receipt DACL does not contain the exact gate/SYSTEM/Administrators set'
}

function Write-AclEvidenceReceipt {
    param(
        [Parameter(Mandatory = $true)]$Details,
        [Parameter(Mandatory = $true)][DateTimeOffset]$StartedUtc,
        [Parameter(Mandatory = $true)][DateTimeOffset]$CompletedUtc
    )

    $receipt = [ordered]@{
        schema_version = 1
        category = 'windows_privileged_acl'
        status = 'passed'
        tag = $Tag
        tag_object = $TagObject
        commit = $Commit
        release_manifest_sha256 = $ReleaseManifestSha256
        evidence_owner = $EvidenceOwner
        timestamps = [ordered]@{
            started_utc = $StartedUtc.ToString('o')
            completed_utc = $CompletedUtc.ToString('o')
        }
        test_counts = [ordered]@{
            total = 12
            passed = 12
            failed = 0
            skipped = 0
            ignored = 0
            unknown = 0
        }
        limitations = @()
        details = $Details
    }
    $json = ($receipt | ConvertTo-Json -Depth 8 -Compress) + "`n"
    $bytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes($json)
    Write-ProtectedCreateNewReceipt -Path $ReceiptPath -Bytes $bytes
}

function Add-FullControlRule {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.DirectorySecurity]$Acl,
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$Sid
    )
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $Sid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $Acl.AddAccessRule($rule)
}

function Set-ProbeRootAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier[]]$AccountSids
    )
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    Add-FullControlRule -Acl $acl -Sid (
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    )
    Add-FullControlRule -Acl $acl -Sid (
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    )
    foreach ($sid in $AccountSids) {
        Add-FullControlRule -Acl $acl -Sid $sid
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-SerctlProtectedAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$ExpectedOwner,
        [Parameter(Mandatory = $true)][bool]$Directory
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-GateCondition (
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) "$Label is a reparse point"
    Assert-GateCondition ([bool]$item.PSIsContainer -eq $Directory) (
        "$Label type does not match the expected directory flag"
    )
    $acl = Get-Acl -LiteralPath $Path
    $actualOwner = $acl.GetOwner(
        [System.Security.Principal.SecurityIdentifier]
    )
    Assert-GateCondition ($actualOwner.Value -ceq $ExpectedOwner.Value) (
        "$Label owner SID does not match the expected owner SID"
    )
    Assert-GateCondition $acl.AreAccessRulesProtected (
        "$Label DACL still inherits from its parent"
    )

    $rules = @(
        $acl.GetAccessRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        )
    )
    Assert-GateCondition ($rules.Count -eq 3) (
        "$Label does not have exactly three explicit ACEs"
    )
    # The SDDL uses OW (Owner Rights, S-1-3-4), not a copied account SID.
    # Verify the object owner separately above and the dynamic owner-rights
    # ACE here, matching serctl's exact production descriptor.
    $expectedSids = @(
        'S-1-3-4',
        'S-1-5-18',
        'S-1-5-32-544'
    ) | Sort-Object -Unique
    $actualSids = @($rules | ForEach-Object { $_.IdentityReference.Value }) |
        Sort-Object -Unique
    Assert-GateCondition (
        (($actualSids -join ',') -ceq ($expectedSids -join ','))
    ) "$Label grants an unexpected identity"

    $requiredInheritance = [System.Security.AccessControl.InheritanceFlags]::None
    if ($Directory) {
        $requiredInheritance =
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    }
    foreach ($rule in $rules) {
        Assert-GateCondition (
            $rule.AccessControlType -eq
                [System.Security.AccessControl.AccessControlType]::Allow
        ) "$Label contains a non-Allow ACE"
        Assert-GateCondition (
            ($rule.FileSystemRights -band
                [System.Security.AccessControl.FileSystemRights]::FullControl) -eq
                [System.Security.AccessControl.FileSystemRights]::FullControl
        ) "$Label ACE is not FullControl"
        Assert-GateCondition ($rule.InheritanceFlags -eq $requiredInheritance) (
            "$Label ACE has unexpected inheritance flags"
        )
        Assert-GateCondition (
            $rule.PropagationFlags -eq
                [System.Security.AccessControl.PropagationFlags]::None
        ) "$Label ACE has unexpected propagation flags"
    }
}

function Invoke-ProbeUser {
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][securestring]$Password,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$HomePath,
        [Parameter(Mandatory = $true)][string]$WorkerPath,
        [Parameter(Mandatory = $true)][string]$CliCopy,
        [Parameter(Mandatory = $true)][string]$ProbeRoot
    )
    $credential = [System.Management.Automation.PSCredential]::new(
        "$env:COMPUTERNAME\$UserName",
        $Password
    )
    $stdout = Join-Path $ProbeRoot "$Mode-$UserName.stdout.txt"
    $stderr = Join-Path $ProbeRoot "$Mode-$UserName.stderr.txt"
    $process = Start-Process `
        -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            $WorkerPath,
            '-Mode',
            $Mode,
            '-HomePath',
            $HomePath,
            '-CliPath',
            $CliCopy
        ) `
        -Credential $credential `
        -LoadUserProfile `
        -WorkingDirectory $ProbeRoot `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -Wait `
        -PassThru
    if ($process.ExitCode -ne 0) {
        $script:probeFailure = switch -CaseSensitive ($Mode) {
            'reparse' {
                if ($process.ExitCode -eq 41) { 'reparse_accepted' }
                elseif ($process.ExitCode -eq 42) { 'reparse_cli_start_failed' }
                elseif ($process.ExitCode -eq 50) { 'reparse_rejection_unproven' }
                else { 'reparse_worker_failed' }
            }
            'owner' {
                if ($process.ExitCode -eq 43) { 'owner_cli_failed' }
                else { 'owner_worker_failed' }
            }
            'observer' {
                if ($process.ExitCode -eq 44) { 'observer_vault_opened' }
                elseif ($process.ExitCode -eq 45) { 'observer_parent_control_failed' }
                elseif ($process.ExitCode -eq 46) { 'observer_vault_lock_readable' }
                elseif ($process.ExitCode -eq 47) { 'observer_lock_denial_unclassified' }
                elseif ($process.ExitCode -eq 48) { 'observer_vault_writable' }
                elseif ($process.ExitCode -eq 49) { 'observer_write_denial_unclassified' }
                else { 'observer_worker_failed' }
            }
            default { 'unknown_worker_failed' }
        }
        $stdoutBytes = if (Test-Path -LiteralPath $stdout -PathType Leaf) {
            (Get-Item -LiteralPath $stdout -Force).Length
        }
        else { 0 }
        $stderrBytes = if (Test-Path -LiteralPath $stderr -PathType Leaf) {
            (Get-Item -LiteralPath $stderr -Force).Length
        }
        else { 0 }
        throw (
            "Windows multi-account ACL gate failed: $Mode probe exited " +
            "$($process.ExitCode); captured output withheld " +
            "(stdout_bytes=$stdoutBytes, stderr_bytes=$stderrBytes)"
        )
    }
}

$safeCliLeaf = Get-ReleaseLogLeafName -Path $CliPath -Fallback 'serctl-cli'
$safeCliBytes = [long]0
$gatePhase = 'preflight'
$probeFailure = 'none'
try {
if ($env:OS -cne 'Windows_NT') {
    throw 'Windows multi-account ACL gate must run on Windows'
}
$receiptValues = @(
    $ReceiptPath,
    $Tag,
    $TagObject,
    $Commit,
    $ReleaseManifestSha256,
    $EvidenceOwner
)
$providedReceiptValues = @(
    $receiptValues | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
)
$receiptRequested = $providedReceiptValues.Count -gt 0
Assert-GateCondition (
    -not $receiptRequested -or $providedReceiptValues.Count -eq $receiptValues.Count
) 'receipt mode requires the complete release identity and evidence owner'
if ($receiptRequested) {
    Assert-SafeReceiptIdentity -Value $EvidenceOwner -Label 'evidence owner'
}
Assert-GateCondition (
    [Environment]::Is64BitOperatingSystem -and [Environment]::Is64BitProcess
) 'the ACL gate requires a native Windows X64 process'
$rustcCommand = Get-Command rustc -ErrorAction SilentlyContinue
Assert-GateCondition ($null -ne $rustcCommand) 'rustc is unavailable for runner identity proof'
$rustcIdentity = @(& $rustcCommand.Source --version --verbose 2>$null)
Assert-GateCondition ($LASTEXITCODE -eq 0) 'rustc runner identity probe failed'
$rustHostLines = @($rustcIdentity | Where-Object { $_ -cmatch '^host: ' })
Assert-GateCondition (
    $rustHostLines.Count -eq 1 -and
    [string]$rustHostLines[0] -ceq 'host: x86_64-pc-windows-msvc'
) 'the ACL gate Rust host is not exactly x86_64-pc-windows-msvc'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
Assert-GateCondition (
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
) 'the runner is not elevated; this gate may not skip account creation'
foreach ($command in @(
    'New-LocalUser',
    'Get-LocalUser',
    'Get-LocalGroupMember',
    'Remove-LocalUser'
)) {
    Assert-GateCondition ($null -ne (Get-Command $command -ErrorAction SilentlyContinue)) (
        "required command '$command' is unavailable"
    )
}

$resolvedCli = [System.IO.Path]::GetFullPath($CliPath)
Assert-GateCondition (Test-Path -LiteralPath $resolvedCli -PathType Leaf) (
    'CLI binary is missing'
)
$cliItem = Get-Item -LiteralPath $resolvedCli -Force -ErrorAction Stop
$safeCliBytes = [long]$cliItem.Length
Assert-GateCondition (
    ($cliItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
) 'CLI binary is a reparse point'
Assert-GateCondition ($cliItem.Length -gt 0) 'CLI binary is empty'
$candidateCliSha256 = (Get-FileHash -LiteralPath $resolvedCli -Algorithm SHA256).Hash
Assert-GateCondition ($candidateCliSha256 -cmatch '^[0-9A-F]{64}$') (
    'CLI SHA-256 is not canonical uppercase hexadecimal'
)
$suffix = [System.Guid]::NewGuid().ToString('N').Substring(0, 8)
$ownerName = "sctlown$suffix"
$observerName = "sctlobs$suffix"
$probeRoot = Join-Path $env:SystemDrive "serctl-acl-e2e-$suffix"
$ownerHome = Join-Path $probeRoot 'owner-home'
$cliCopy = Join-Path $probeRoot 'serctl_cli.exe'
$workerPath = Join-Path $probeRoot 'acl-worker.ps1'
$ownerPlain = "Aa9!owner$suffix"
$observerPlain = "Aa9!observer$suffix"
$ownerPassword = ConvertTo-SecureString $ownerPlain -AsPlainText -Force
$observerPassword = ConvertTo-SecureString $observerPlain -AsPlainText -Force
$ownerCreated = $false
$observerCreated = $false
$gateResult = $null
$startedUtc = [DateTimeOffset]::UtcNow

try {
    $gatePhase = 'create_accounts'
    Assert-GateCondition (-not (Test-Path -LiteralPath $probeRoot)) (
        'probe root already exists; refusing to reuse it'
    )
    New-LocalUser `
        -Name $ownerName `
        -Password $ownerPassword `
        -AccountNeverExpires `
        -PasswordNeverExpires | Out-Null
    $ownerCreated = $true
    New-LocalUser `
        -Name $observerName `
        -Password $observerPassword `
        -AccountNeverExpires `
        -PasswordNeverExpires | Out-Null
    $observerCreated = $true
    $gatePhase = 'validate_accounts'
    $ownerSid = (Get-LocalUser -Name $ownerName).SID
    $observerSid = (Get-LocalUser -Name $observerName).SID
    Assert-GateCondition ($ownerSid.Value -cne $observerSid.Value) (
        'owner and observer SIDs are not distinct'
    )
    $administratorsSid =
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $administratorMemberSids = @(
        Get-LocalGroupMember -SID $administratorsSid -ErrorAction Stop |
            ForEach-Object { $_.SID.Value }
    )
    Assert-GateCondition (-not ($administratorMemberSids -contains $ownerSid.Value)) (
        'owner probe account is an administrator'
    )
    Assert-GateCondition (
        -not ($administratorMemberSids -contains $observerSid.Value)
    ) 'observer probe account is an administrator'

    $gatePhase = 'prepare_fixture'
    [System.IO.Directory]::CreateDirectory($probeRoot) | Out-Null
    Set-ProbeRootAcl -Path $probeRoot -AccountSids @($ownerSid, $observerSid)
    Copy-Item -LiteralPath $resolvedCli -Destination $cliCopy
    $worker = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Mode,
    [Parameter(Mandatory = $true)][string]$HomePath,
    [Parameter(Mandatory = $true)][string]$CliPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$env:USERPROFILE = $HomePath
$env:HOME = $HomePath

$workerIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$workerPrincipal = [System.Security.Principal.WindowsPrincipal]::new(
    $workerIdentity
)
if ($workerPrincipal.IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw 'probe account has an administrator token'
}

function Test-IsAccessDeniedError {
    param([Parameter(Mandatory = $true)]$ErrorRecord)

    $exception = $ErrorRecord.Exception
    for ($depth = 0; $depth -lt 8 -and $null -ne $exception; $depth++) {
        if ($exception -is [System.UnauthorizedAccessException]) { return $true }
        if (
            ($exception -is [System.IO.IOException] -or
                $exception -is [System.ComponentModel.Win32Exception]) -and
            (($exception.HResult -band 0xffff) -eq 5)
        ) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}

function Invoke-CliList {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $CliPath
    $startInfo.Arguments = 'list'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            return [pscustomobject]@{
                ExitCode = 42
                ReparseRejected = $false
            }
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        # Drain both pipes without forwarding profile metadata or error details.
        $null = $stdoutTask.GetAwaiter().GetResult()
        $stderrText = $stderrTask.GetAwaiter().GetResult()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            ReparseRejected = $stderrText.Contains(
                'protected directory path is not a non-reparse directory'
            )
        }
    }
    finally {
        $process.Dispose()
    }
}

if ($Mode -eq 'owner') {
    [System.IO.Directory]::CreateDirectory($HomePath) | Out-Null
    if ((Invoke-CliList).ExitCode -ne 0) { exit 43 }
    exit 0
}
if ($Mode -eq 'reparse') {
    $result = Invoke-CliList
    if ($result.ExitCode -eq 0) {
        exit 41
    }
    if ($result.ExitCode -eq 42) { exit 42 }
    if (-not $result.ReparseRejected) { exit 50 }
    exit 0
}
if ($Mode -ne 'observer') { throw 'unknown worker mode' }

# Prove the observer can reach and write the deliberately shared parent. A
# later denial therefore comes from serctl's protected child, not an
# inaccessible test root or a failed secondary logon.
$control = Join-Path $HomePath 'observer-parent-control.txt'
try {
    [System.IO.File]::WriteAllText($control, 'control')
    [System.IO.File]::Delete($control)
}
catch { exit 45 }

if ((Invoke-CliList).ExitCode -eq 0) { exit 44 }
$vaultDirectory = Join-Path $HomePath '.serctl'
$lockPath = Join-Path $vaultDirectory 'vault.lock'
$readDenied = $false
try {
    $handle = [System.IO.File]::Open(
        $lockPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
    )
    $handle.Dispose()
}
catch {
    if (Test-IsAccessDeniedError -ErrorRecord $_) {
        $readDenied = $true
    }
    else { exit 47 }
}
if (-not $readDenied) { exit 46 }

$createDenied = $false
try {
    $handle = [System.IO.File]::Open(
        (Join-Path $vaultDirectory 'observer-created'),
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    $handle.Dispose()
}
catch {
    if (Test-IsAccessDeniedError -ErrorRecord $_) {
        $createDenied = $true
    }
    else { exit 49 }
}
if (-not $createDenied) { exit 48 }
exit 0
'@
    [System.IO.File]::WriteAllText(
        $workerPath,
        $worker,
        [System.Text.UTF8Encoding]::new($false)
    )

    $gatePhase = 'reparse_probe'
    $reparseHome = Join-Path $probeRoot 'reparse-home'
    $reparseTarget = Join-Path $probeRoot 'reparse-target'
    $reparseSentinel = Join-Path $reparseTarget 'sentinel.txt'
    [System.IO.Directory]::CreateDirectory($reparseHome) | Out-Null
    [System.IO.Directory]::CreateDirectory($reparseTarget) | Out-Null
    [System.IO.File]::WriteAllText($reparseSentinel, 'serctl-acl-reparse-sentinel')
    New-Item `
        -ItemType Junction `
        -Path (Join-Path $reparseHome '.serctl') `
        -Target $reparseTarget `
        -ErrorAction Stop | Out-Null
    $reparseItem = Get-Item -LiteralPath (Join-Path $reparseHome '.serctl') -Force
    Assert-GateCondition (
        ($reparseItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) 'reparse fixture is not a reparse point'
    Invoke-ProbeUser `
        -UserName $ownerName `
        -Password $ownerPassword `
        -Mode reparse `
        -HomePath $reparseHome `
        -WorkerPath $workerPath `
        -CliCopy $cliCopy `
        -ProbeRoot $probeRoot
    $reparseEntries = @(Get-ChildItem -LiteralPath $reparseTarget -Force)
    Assert-GateCondition ($reparseEntries.Count -eq 1) (
        'reparse target was modified during rejection probe'
    )
    Assert-GateCondition (
        [System.IO.File]::ReadAllText($reparseSentinel) -ceq
            'serctl-acl-reparse-sentinel'
    ) 'reparse target sentinel changed during rejection probe'

    $gatePhase = 'owner_initialize'
    Invoke-ProbeUser `
        -UserName $ownerName `
        -Password $ownerPassword `
        -Mode owner `
        -HomePath $ownerHome `
        -WorkerPath $workerPath `
        -CliCopy $cliCopy `
        -ProbeRoot $probeRoot
    $vaultDirectory = Join-Path $ownerHome '.serctl'
    $vaultLock = Join-Path $vaultDirectory 'vault.lock'
    Assert-GateCondition (Test-Path -LiteralPath $vaultDirectory -PathType Container) (
        'owner CLI did not create the protected vault directory'
    )
    Assert-GateCondition (Test-Path -LiteralPath $vaultLock -PathType Leaf) (
        'owner CLI did not create the protected vault lock'
    )
    $gatePhase = 'verify_owner_acl'
    Assert-SerctlProtectedAcl `
        -Path $vaultDirectory `
        -Label 'protected vault directory' `
        -ExpectedOwner $ownerSid `
        -Directory $true
    Assert-SerctlProtectedAcl `
        -Path $vaultLock `
        -Label 'protected vault lock' `
        -ExpectedOwner $ownerSid `
        -Directory $false

    $gatePhase = 'observer_denial'
    Invoke-ProbeUser `
        -UserName $observerName `
        -Password $observerPassword `
        -Mode observer `
        -HomePath $ownerHome `
        -WorkerPath $workerPath `
        -CliCopy $cliCopy `
        -ProbeRoot $probeRoot
    $gatePhase = 'owner_reopen'
    Invoke-ProbeUser `
        -UserName $ownerName `
        -Password $ownerPassword `
        -Mode owner `
        -HomePath $ownerHome `
        -WorkerPath $workerPath `
        -CliCopy $cliCopy `
        -ProbeRoot $probeRoot

    $gatePhase = 'complete'
    $gateResult = [ordered]@{
        runner = [ordered]@{
            label = 'windows-acl-gate'
            os = 'Windows'
            arch = 'X64'
            rust_host = 'x86_64-pc-windows-msvc'
        }
        candidate_cli_sha256 = $candidateCliSha256
        owner_sid = $ownerSid.Value
        observer_sid = $observerSid.Value
        distinct_sids = $true
        parent_control_passed = $true
        observer_read_denied = $true
        observer_write_denied = $true
        owner_reopen_passed = $true
        dacl_protected = $true
        reparse_point_rejected = $true
        owner_rights_restricted = $true
        system_full_control = $true
        administrators_full_control = $true
        inheritance_protected = $true
        cleanup_passed = $true
    }
}
finally {
    $ownerPlain = $null
    $observerPlain = $null
    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $probeRoot) {
        try {
            $cleanupItem = Get-Item -LiteralPath $probeRoot -Force -ErrorAction Stop
            if (($cleanupItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'refusing recursive cleanup of reparse-point probe root'
            }
            Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction Stop
            Assert-GateCondition (
                -not (Test-Path -LiteralPath $probeRoot -ErrorAction Stop)
            ) 'probe root still exists after removal'
        }
        catch {
            $cleanupFailures.Add('probe_root_cleanup_failed')
        }
    }
    if ($observerCreated) {
        try {
            Remove-LocalUser -Name $observerName -ErrorAction Stop
            $remainingObserver = @(
                Get-LocalUser -ErrorAction Stop |
                    Where-Object { $_.Name -ceq $observerName }
            )
            Assert-GateCondition ($remainingObserver.Count -eq 0) (
                'observer account still exists after removal'
            )
        }
        catch {
            $cleanupFailures.Add('observer_account_cleanup_failed')
        }
    }
    if ($ownerCreated) {
        try {
            Remove-LocalUser -Name $ownerName -ErrorAction Stop
            $remainingOwner = @(
                Get-LocalUser -ErrorAction Stop |
                    Where-Object { $_.Name -ceq $ownerName }
            )
            Assert-GateCondition ($remainingOwner.Count -eq 0) (
                'owner account still exists after removal'
            )
        }
        catch {
            $cleanupFailures.Add('owner_account_cleanup_failed')
        }
    }
    if ($cleanupFailures.Count -gt 0) {
        $gatePhase = 'cleanup'
        throw (
            'Windows multi-account ACL gate cleanup failed closed: ' +
            ($cleanupFailures -join '; ')
        )
    }
}
$completedUtc = [DateTimeOffset]::UtcNow
if ($receiptRequested) {
    Write-AclEvidenceReceipt `
        -Details $gateResult `
        -StartedUtc $startedUtc `
        -CompletedUtc $completedUtc
}
$gateResult | ConvertTo-Json -Compress | Write-Output
}
catch {
    [Console]::Error.WriteLine(
        'Windows multi-account ACL gate failed: ' +
        (Format-ReleaseLogRecord `
            -Category windows_acl_gate_failed `
            -LeafName $safeCliLeaf `
            -Bytes $safeCliBytes) +
        "; phase=$gatePhase; probe=$probeFailure"
    )
    exit 1
}
