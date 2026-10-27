# ==============================================================================
# CyberLab OS — Bootstrap Local de Ferramentas no Windows PowerShell (.cyberlab\bin)
# ==============================================================================
# Baixa binários standalone open-source opcionais (nuclei.exe e ffuf.exe — MIT)
# direto para .cyberlab\bin\ dentro do projeto, sem poluir o PATH global do Windows.
#
# Uso no PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\script\bootstrap-local-tools.ps1
# ==============================================================================

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
$BinDir = Join-Path $RootDir ".cyberlab\bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

Write-Host "[CyberLab OS] Diretorio local de binarios: $BinDir"

# 1. ProjectDiscovery Nuclei (MIT)
$NucleiVer = "3.3.7"
$NucleiExe = Join-Path $BinDir "nuclei.exe"
if (-not (Test-Path $NucleiExe)) {
  Write-Host "[CyberLab OS] Baixando Nuclei v$NucleiVer (MIT) para Windows amd64..."
  $TmpZip = Join-Path $env:TEMP "nuclei_win.zip"
  $TmpExtract = Join-Path $env:TEMP "nuclei_extract"
  Invoke-WebRequest -Uri "https://github.com/projectdiscovery/nuclei/releases/download/v$NucleiVer/nuclei_${NucleiVer}_windows_amd64.zip" -OutFile $TmpZip
  if (Test-Path $TmpExtract) { Remove-Item -Recurse -Force $TmpExtract }
  Expand-Archive -Path $TmpZip -DestinationPath $TmpExtract -Force
  Copy-Item (Join-Path $TmpExtract "nuclei.exe") $NucleiExe -Force
  Remove-Item -Force $TmpZip
  Remove-Item -Recurse -Force $TmpExtract
  Write-Host "[CyberLab OS] Instalado: $NucleiExe"
} else {
  Write-Host "[CyberLab OS] nuclei.exe ja presente em $NucleiExe"
}

# 2. ffuf (MIT)
$FfufVer = "2.1.0"
$FfufExe = Join-Path $BinDir "ffuf.exe"
if (-not (Test-Path $FfufExe)) {
  Write-Host "[CyberLab OS] Baixando ffuf v$FfufVer (MIT) para Windows amd64..."
  $TmpZip = Join-Path $env:TEMP "ffuf_win.zip"
  $TmpExtract = Join-Path $env:TEMP "ffuf_extract"
  Invoke-WebRequest -Uri "https://github.com/ffuf/ffuf/releases/download/v$FfufVer/ffuf_${FfufVer}_windows_amd64.zip" -OutFile $TmpZip
  if (Test-Path $TmpExtract) { Remove-Item -Recurse -Force $TmpExtract }
  Expand-Archive -Path $TmpZip -DestinationPath $TmpExtract -Force
  Copy-Item (Join-Path $TmpExtract "ffuf.exe") $FfufExe -Force
  Remove-Item -Force $TmpZip
  Remove-Item -Recurse -Force $TmpExtract
  Write-Host "[CyberLab OS] Instalado: $FfufExe"
} else {
  Write-Host "[CyberLab OS] ffuf.exe ja presente em $FfufExe"
}

Write-Host ""
Write-Host "[CyberLab OS] Bootstrap PowerShell concluido com sucesso!"
