<#
  Runs the ai-dlp proxy (started by the "ai-dlp proxy" scheduled task as SYSTEM).
  Restarts mitmdump if it exits, and appends its output to the proxy log.
#>
$ErrorActionPreference = 'Continue'
$Prefix = $PSScriptRoot
$Conf   = Join-Path $env:ProgramData 'ai-dlp'
$Log    = Join-Path $Conf 'logs\proxy.log'
$env:PATH = (Join-Path $Prefix 'gitleaks') + ';' + $env:PATH
$env:PYTHONUNBUFFERED = '1'
$mitmdump = Join-Path $Prefix 'venv\Scripts\mitmdump.exe'

while ($true) {
    & $mitmdump --mode local `
        --set "confdir=$(Join-Path $Conf 'state')" --set upstream_cert=false `
        --set flow_detail=0 --set termlog_verbosity=info `
        -s (Join-Path $Prefix 'core\ai_dlp.py') *>> $Log
    Add-Content -Path $Log -Value "$(Get-Date -Format o) mitmdump exited ($LASTEXITCODE); restarting in 2 s"
    Start-Sleep -Seconds 2
}
