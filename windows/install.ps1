#Requires -RunAsAdministrator
<#
  ai-dlp installer for Windows (EXPERIMENTAL: not yet tested on Windows).

  Prerequisite: Python 3.12 installed for all users, e.g.
      winget install -e --id Python.Python.3.12 --scope machine
  Run from an Administrator PowerShell in the repository folder:
      powershell -ExecutionPolicy Bypass -File .\windows\install.ps1

  Traffic capture uses mitmproxy's local capture mode (WinDivert). Installs the proxy
  as a scheduled task running as SYSTEM, but does not start it; turn it on with `ai-dlp on`.
#>
param(
    # Use this python.exe instead of `py -3.12` (it must be an all-users install that
    # ordinary users cannot modify; the installer checks).
    [string]$Python = ''
)
$ErrorActionPreference = 'Stop'
$MitmproxyVersion = '12.2.3'
$GitleaksVersion  = '8.30.1'

$Src    = $PSScriptRoot
$Core   = (Resolve-Path (Join-Path $Src '..\core')).Path
$Prefix = Join-Path $env:ProgramFiles 'ai-dlp'
$Conf   = Join-Path $env:ProgramData 'ai-dlp'
$State  = Join-Path $Conf 'state'
$Logs   = Join-Path $Conf 'logs'
$Task   = 'ai-dlp proxy'
$System = '*S-1-5-18'       # LocalSystem
$Admins = '*S-1-5-32-544'   # BUILTIN\Administrators
$Users  = '*S-1-5-32-545'   # BUILTIN\Users
$CodeDir = Join-Path $Prefix 'core'   # code runs as SYSTEM: keep it where only admins can write

function Step($Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }

Step 'Checking for Python 3.12'
if ($Python) {
    $BasePy = @($Python)
} else {
    if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
        throw 'The Python launcher (py) was not found. Install Python first: winget install -e --id Python.Python.3.12 --scope machine'
    }
    $BasePy = @('py', '-3.12')
}
& $BasePy[0] @($BasePy | Select-Object -Skip 1) -c 'import sys; assert sys.version_info[:2] == (3, 12)' 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 not found. Install it: winget install -e --id Python.Python.3.12 --scope machine' }

# The proxy runs as SYSTEM and loads Python's runtime from the base installation, so
# that installation must be one ordinary users cannot modify: an all-users install
# (Program Files), not a per-user one under C:\Users.
function Assert-AdminOnlyWritable([string]$Path) {
    $full = (Resolve-Path $Path).Path
    if ($full -like "$env:SystemDrive\Users\*") {
        throw "Python at $full is a per-user install. Install it for all users: winget install -e --id Python.Python.3.12 --scope machine"
    }
    $untrusted = 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4'   # Everyone, Authenticated Users, Users, Interactive
    $acl = Get-Acl $full
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
        if ($sid -in $untrusted -and $rule.FileSystemRights.ToString() -match 'Write|Modify|FullControl|CreateFiles|AppendData|ChangePermissions|TakeOwnership') {
            throw "Ordinary users can modify $full ($($rule.IdentityReference): $($rule.FileSystemRights)); refusing to run it as SYSTEM."
        }
    }
}
$basePython = (& $BasePy[0] @($BasePy | Select-Object -Skip 1) -c 'import sys; print(sys.base_prefix)').Trim()
Assert-AdminOnlyWritable $basePython

Step "Python environment with mitmproxy $MitmproxyVersion (in $Prefix)"
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
$Py = Join-Path $Prefix 'venv\Scripts\python.exe'
if (-not (Test-Path $Py)) { & $BasePy[0] @($BasePy | Select-Object -Skip 1) -m venv (Join-Path $Prefix 'venv') }
Assert-AdminOnlyWritable ((& $Py -c 'import sys; print(sys.base_prefix)').Trim())   # an older venv may point elsewhere
& $Py -m pip install --quiet --disable-pip-version-check "mitmproxy==$MitmproxyVersion"
if ($LASTEXITCODE -ne 0) { throw 'Installing mitmproxy failed.' }

Step "gitleaks $GitleaksVersion (checksum verified)"
$zip  = "gitleaks_${GitleaksVersion}_windows_x64.zip"
$base = "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVersion"
$tmp  = Join-Path $env:TEMP ("ai-dlp-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$zip" -OutFile (Join-Path $tmp $zip)
    Invoke-WebRequest -UseBasicParsing -Uri "$base/gitleaks_${GitleaksVersion}_checksums.txt" -OutFile (Join-Path $tmp 'sums.txt')
    $line = Select-String -Path (Join-Path $tmp 'sums.txt') -Pattern ([regex]::Escape($zip)) | Select-Object -First 1
    if (-not $line) { throw "No checksum listed for $zip" }
    $want = ($line.Line -split '\s+')[0]
    $have = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $zip)).Hash
    if ($have -ne $want) { throw "gitleaks checksum mismatch (expected $want, got $have)" }
    Expand-Archive -Path (Join-Path $tmp $zip) -DestinationPath (Join-Path $Prefix 'gitleaks') -Force
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

Step 'Installing files'
# ProgramData lets ordinary users create folders and files. Anything in $Conf that an
# ordinary user created (a planted CA key, domain list or secret list) must stop the
# install. Check every item, lock the folder, then check again: whatever slipped in
# before the lock took effect is caught by the second check.
function Get-TrustedOwners {
    $sids = [System.Collections.Generic.HashSet[string]]::new([string[]]@('S-1-5-18', 'S-1-5-32-544'))
    [void]$sids.Add([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)   # this elevated admin
    try { Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [void]$sids.Add($_.SID.Value) } } catch { }
    $sids
}
function Assert-TrustedTree([string]$Path) {
    $trusted = Get-TrustedOwners
    $items = @(Get-Item -LiteralPath $Path -Force) + @(Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop)
    foreach ($item in $items) {
        $owner = (Get-Acl -LiteralPath $item.FullName).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if (-not $trusted.Contains($owner)) {
            throw "$($item.FullName) is owned by $owner, which is not SYSTEM or an administrator. Inspect and remove $Path, then run the installer again."
        }
    }
}
New-Item -ItemType Directory -Force -Path $Conf | Out-Null
Assert-TrustedTree $Conf
icacls $Conf /inheritance:r /grant:r "${System}:(OI)(CI)F" "${Admins}:(OI)(CI)F" "${Users}:(OI)(CI)RX" | Out-Null
Assert-TrustedTree $Conf
icacls $Conf /setowner $Admins /T /C | Out-Null   # normalise only after both checks passed
New-Item -ItemType Directory -Force -Path $State, $Logs | Out-Null
icacls $State /inheritance:r /grant:r "${System}:(OI)(CI)F" "${Admins}:(OI)(CI)F" | Out-Null
New-Item -ItemType Directory -Force -Path $CodeDir | Out-Null
foreach ($f in 'ai_dlp.py', 'make_ca.py', 'aidlp_tool.py') { Copy-Item -Force (Join-Path $Core $f) $CodeDir }
Copy-Item -Force (Join-Path $Core 'gitleaks.toml') $Conf
if (-not (Test-Path (Join-Path $Conf 'domains.txt'))) { Copy-Item (Join-Path $Core 'domains.txt') $Conf }   # keep your edits
$secrets = Join-Path $State 'secrets.txt'   # SYSTEM and Administrators only
if (-not (Test-Path $secrets)) { New-Item -ItemType File -Path $secrets | Out-Null }
icacls $secrets /inheritance:r /grant:r "${System}:F" "${Admins}:F" | Out-Null
foreach ($f in 'ai-dlp.ps1', 'ai-dlp.cmd', 'run-proxy.ps1') { Copy-Item -Force (Join-Path $Src $f) $Prefix }

Step 'Certificate authority limited to the listed domains'
$ca = Join-Path $Conf 'ca.pem'
$result = & $Py -I (Join-Path $CodeDir 'make_ca.py') (Join-Path $Conf 'domains.txt') $State $ca
if ($LASTEXITCODE -ne 0) { throw 'Creating the certificate authority failed.' }
& $Py -I (Join-Path $CodeDir 'make_ca.py') --verify $ca (Join-Path $Conf 'domains.txt')
if ($LASTEXITCODE -ne 0) { throw 'Refusing to trust the generated certificate (see above).' }
$result | ForEach-Object { Write-Host $_ }
$newCa = $result -contains 'ca: new'
if ($newCa) {
    Get-ChildItem Cert:\LocalMachine\Root |
        Where-Object { $_.Subject -like '*ai-dlp local inspection CA*' } |
        Remove-Item
}

Step 'Trusting the CA (Local Machine > Trusted Root Certification Authorities)'
certutil -f -addstore Root $ca | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Adding the CA to the Root store failed.' }

Step 'NODE_EXTRA_CA_CERTS for Node apps (machine environment)'
$current = [Environment]::GetEnvironmentVariable('NODE_EXTRA_CA_CERTS', 'Machine')
if (-not $current) { [Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', $ca, 'Machine') }
elseif ($current -ne $ca) { Write-Warning "NODE_EXTRA_CA_CERTS is already set to $current; left unchanged." }

Step 'Browsers (Chrome, Edge, Brave, Firefox): no QUIC/HTTP3 and no Encrypted Client Hello (both would hide or skip the proxy)'
foreach ($key in 'HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
                 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave') {
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    New-ItemProperty -Path $key -Name QuicAllowed -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $key -Name EncryptedClientHelloEnabled -Value 0 -PropertyType DWord -Force | Out-Null
}
# Firefox: no DNS-over-HTTPS, no ECH, no HTTP/3
$ff = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
$doh = "$ff\DNSOverHTTPS"
if (-not (Test-Path $doh)) { New-Item -Path $doh -Force | Out-Null }
New-ItemProperty -Path $doh -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $doh -Name Locked -Value 1 -PropertyType DWord -Force | Out-Null
$prefs = '{"network.dns.echconfig.enabled":{"Value":false,"Status":"locked"},"network.dns.http3_echconfig.enabled":{"Value":false,"Status":"locked"},"network.http.http3.enable":{"Value":false,"Status":"locked"}}'
New-ItemProperty -Path $ff -Name Preferences -Value $prefs -PropertyType String -Force | Out-Null

Step "Adding $Prefix to the system PATH (for the ai-dlp command)"
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (($path -split ';') -notcontains $Prefix) {
    [Environment]::SetEnvironmentVariable('Path', ($path.TrimEnd(';') + ';' + $Prefix), 'Machine')
}

Step "Scheduled task '$Task' (installed, not started)"
$existing = Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
$wasOn = $existing -and $existing.State -ne 'Disabled'
$runner = Join-Path $Prefix 'run-proxy.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runner`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
if ($wasOn) {
    & (Join-Path $Prefix 'ai-dlp.ps1') off | Out-Null
    & (Join-Path $Prefix 'ai-dlp.ps1') on | Out-Null
    Write-Host 'The proxy was on: restarted it with the new files.'
} else {
    Disable-ScheduledTask -TaskName $Task | Out-Null
}

if ($newCa) { Write-Host "`nNOTE: a new certificate authority was issued. Restart your browser and AI apps." -ForegroundColor Yellow }

Write-Host @"

Installed. Open a NEW terminal (for the updated PATH), then:
  1. Turn it on:            ai-dlp on
  2. Check it works:        ai-dlp test --claude
  3. Add your own secrets:  ai-dlp add-secrets path\to\.env     (from an Administrator terminal)
  4. Claude Code: add  "env": {"NODE_EXTRA_CA_CERTS": "$($ca -replace '\\','\\')"}  to %USERPROFILE%\.claude\settings.json

Unlike Linux, if the proxy is stopped, traffic flows normally (unscanned): keep it on.
Undo everything with: powershell -ExecutionPolicy Bypass -File .\windows\uninstall.ps1  (as Administrator)
"@
