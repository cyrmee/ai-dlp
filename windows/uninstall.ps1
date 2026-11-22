#Requires -RunAsAdministrator
<#
  Remove ai-dlp from Windows: proxy task, CA trust, CA key, browser policies, files.
  Python is left installed.
#>
$ErrorActionPreference = 'Continue'
$Prefix = Join-Path $env:ProgramFiles 'ai-dlp'
$Conf   = Join-Path $env:ProgramData 'ai-dlp'
$Task   = 'ai-dlp proxy'

Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
Get-Process -Name mitmdump -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$Prefix*" } | Stop-Process -Force

Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object { $_.Subject -like '*ai-dlp local inspection CA*' } |
    Remove-Item

Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS' -Recurse -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox' -Name Preferences -ErrorAction SilentlyContinue
foreach ($key in 'HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
                 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave') {
    if (Test-Path $key) {
        Remove-ItemProperty -Path $key -Name QuicAllowed, EncryptedClientHelloEnabled -ErrorAction SilentlyContinue
    }
}

$ca = Join-Path $Conf 'ca.pem'
if ([Environment]::GetEnvironmentVariable('NODE_EXTRA_CA_CERTS', 'Machine') -eq $ca) {
    [Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', $null, 'Machine')
}
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
[Environment]::SetEnvironmentVariable('Path', (($path -split ';') | Where-Object { $_ -and $_ -ne $Prefix }) -join ';', 'Machine')

Remove-Item -Recurse -Force $Prefix, $Conf -ErrorAction SilentlyContinue
'ai-dlp removed.'
