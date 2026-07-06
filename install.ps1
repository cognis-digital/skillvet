<#
.SYNOPSIS
  skillvet installer (Windows PowerShell). Stdlib-only core, no runtime deps.
.EXAMPLE
  .\install.ps1
  .\install.ps1 -Content   # also install the optional shrike-sec content scan
#>
param([switch]$Content)

$ErrorActionPreference = "Stop"
$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }

try { & $py --version | Out-Null } catch {
  Write-Error "skillvet: need Python 3.10+ on PATH (set `$env:PYTHON to override)"; exit 1
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = if ($Content) { "$here[content]" } else { $here }

Write-Host "Installing skillvet$(if ($Content) {' [content]'}) with $(& $py --version)"
if ($Content) {
  & $py -m pip install --upgrade "$here[content]"
} else {
  & $py -m pip install --upgrade "$here"
}

Write-Host ""
Write-Host "Installed. Try:"
Write-Host "  skillvet vet .\some-skill"
Write-Host "  skillvet vet .\some-skill -f sarif > skillvet.sarif"
