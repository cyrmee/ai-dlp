<#
  ai-dlp control command for Windows (EXPERIMENTAL). Called through ai-dlp.cmd.
#>
param(
    [Parameter(Position = 0)][string]$Command = 'help',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest = @()
)
$Prefix = $PSScriptRoot
$Conf   = Join-Path $env:ProgramData 'ai-dlp'
$Py     = Join-Path $Prefix 'venv\Scripts\python.exe'
$CA     = Join-Path $Conf 'ca.pem'
$Tool   = Join-Path $Prefix 'core\aidlp_tool.py'
$Task   = 'ai-dlp proxy'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Re-run this command in an elevated window when needed.
function Assert-Admin {
    if (Test-Admin) { return }
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", $Command) + $Rest
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -ArgumentList $argList
    exit
}

function Get-ProxyProcess {
    Get-Process -Name mitmdump -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$Prefix*" }
}

switch ($Command) {
    'status' {
        if (-not (Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue)) { 'ai-dlp is not installed'; break }
        if (Get-ProxyProcess) { 'proxy: running (inspecting)' } else { 'proxy: stopped (AI traffic is NOT scanned)' }
    }
    'on' {
        Assert-Admin
        Enable-ScheduledTask -TaskName $Task | Out-Null
        Start-ScheduledTask -TaskName $Task
        'proxy: started. Restart AI apps that were running before the CA was installed.'
    }
    'off' {
        Assert-Admin
        Disable-ScheduledTask -TaskName $Task | Out-Null
        Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
        Get-ProxyProcess | Stop-Process -Force
        'proxy: stopped (AI traffic is NOT scanned)'
    }
    'test'    { & $Py -I $Tool selftest $CA @Rest; exit $LASTEXITCODE }
    'domains' { & $Py -I $Tool domains (Join-Path $Conf 'domains.txt') $CA }
    'log'     { Get-Content -Path (Join-Path $Conf 'logs\events.jsonl') -Tail 20 -Wait }
    'add-secrets' {
        if (-not (Test-Admin)) { Write-Error 'Run add-secrets from an Administrator terminal.'; exit 1 }
        & $Py -I $Tool add-secrets (Join-Path $Conf 'state\secrets.txt') @Rest
    }
    default {
        @'
ai-dlp: redact secrets from everything sent to AI services

  ai-dlp status              is the proxy running
  ai-dlp domains             inspected domains, and whether the CA covers each
  ai-dlp on                  start the proxy (captures all apps; listed domains are inspected)
  ai-dlp off                 stop the proxy (AI traffic goes out unscanned!)
  ai-dlp test [--claude]     check redaction, passthrough of other sites, and Claude Code
  ai-dlp log                 follow redaction/block events
  ai-dlp add-secrets FILE... add secret values (.env files; --pgpass FILE); Administrator
'@
    }
}
