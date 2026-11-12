# ==============================================================================
# Sentinela HIDS - Script de Instalação Automatizado para Windows
# Repositório: https://github.com/SirEntr0pyy/sentimela
# Licença: MIT
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$NoShortcut,
    [switch]$NoPath
)

$ErrorActionPreference = "Stop"

$Repo = "SirEntr0pyy/sentimela"
$BinaryName = "sentinela.exe"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\Sentinela"
$TargetBin = Join-Path $InstallDir $BinaryName

Write-Host @"
   ___           _   _            _       
  / __| ___ _ _ | |_(_)_ _  ___  | | __ _ 
  \__ \/ -_) ' \|  _| | ' \/ -_) | |/ _` |
  |___/\___|_||_|\__|_|_||_\___| |_|\__,_|
      Honeypot & Intrusion Detection System
"@ -ForegroundColor Cyan

Write-Host "`n==> A iniciar a instalacao do Sentinela no Windows..." -ForegroundColor Green

# 1. Cria a diretoria de instalacao se nao existir
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "  • Diretoria criada: $InstallDir" -ForegroundColor Gray
}

# 2. Localiza o executavel (local ou descarrega do GitHub)
$LocalBin = Join-Path $PSScriptRoot "..\sentinela.exe"
$SameDirBin = Join-Path $PSScriptRoot "sentinela.exe"
$CurrentDirBin = ".\sentinela.exe"

if (Test-Path $SameDirBin) {
    Write-Host "  • Binario encontrado no mesmo diretorio." -ForegroundColor Yellow
    Copy-Item $SameDirBin -Destination $TargetBin -Force
} elseif (Test-Path $LocalBin) {
    Write-Host "  • Binario encontrado na raiz do projeto." -ForegroundColor Yellow
    Copy-Item $LocalBin -Destination $TargetBin -Force
} elseif (Test-Path $CurrentDirBin) {
    Write-Host "  • Binario encontrado no diretorio atual." -ForegroundColor Yellow
    Copy-Item $CurrentDirBin -Destination $TargetBin -Force
} else {
    Write-Host "  • A descarregar a versao mais recente das Releases do GitHub..." -ForegroundColor Cyan
    $AssetUrl = "https://github.com/$Repo/releases/latest/download/sentinela-windows-x64.zip"
    $ZipPath = Join-Path $env:TEMP "sentinela-windows-x64.zip"
    $TempExtract = Join-Path $env:TEMP "sentinela-extract-$(Get-Random)"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $AssetUrl -OutFile $ZipPath -UseBasicParsing

    Expand-Archive -Path $ZipPath -DestinationPath $TempExtract -Force
    $ExtractedExe = Join-Path $TempExtract "sentinela.exe"

    if (Test-Path $ExtractedExe) {
        Copy-Item $ExtractedExe -Destination $TargetBin -Force
    } else {
        # Procura recursivamente se estava numa subpasta
        $Found = Get-ChildItem -Path $TempExtract -Filter "sentinela.exe" -Recurse | Select-Object -First 1
        if ($Found) {
            Copy-Item $Found.FullName -Destination $TargetBin -Force
        } else {
            throw "Nao foi possivel encontrar sentinela.exe no arquivo descarregado."
        }
    }

    # Limpeza
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $TempExtract -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "  • Ficheiro instalado em: $TargetBin" -ForegroundColor Green

# 3. Adiciona ao PATH do Utilizador (se solicitado)
if (-not $NoPath) {
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -split ";" -notcontains $InstallDir) {
        Write-Host "  • A adicionar $InstallDir a variavel de ambiente PATH..." -ForegroundColor Cyan
        $NewPath = if ($UserPath) { "$UserPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        $env:Path = "$env:Path;$InstallDir"
        Write-Host "    ✓ PATH atualizado com sucesso!" -ForegroundColor Green
    } else {
        Write-Host "  • $InstallDir ja se encontra no PATH." -ForegroundColor Gray
    }
}

# 4. Cria Atalho no Ambiente de Trabalho (Desktop)
if (-not $NoShortcut) {
    try {
        $DesktopPath = [Environment]::GetFolderPath("Desktop")
        $ShortcutPath = Join-Path $DesktopPath "Sentinela HIDS.lnk"
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = $TargetBin
        $Shortcut.WorkingDirectory = $InstallDir
        $Shortcut.Description = "Sentinela - Honeypot & Network Intrusion Detection System"
        $Shortcut.Save()
        Write-Host "  • Atalho criado no Ambiente de Trabalho: 'Sentinela HIDS'" -ForegroundColor Green
    } catch {
        Write-Host "  ! Aviso: Nao foi possivel criar o atalho no Desktop ($($_))" -ForegroundColor Yellow
    }
}

Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host "       ✓ SENTINELA INSTALADO COM SUCESSO NO WINDOWS!                  " -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "  Localizacao: $TargetBin"
Write-Host "`nComo iniciar:"
Write-Host "  • Abre uma nova janela do PowerShell ou Terminal e escreve:"
Write-Host "    sentinela" -ForegroundColor Cyan
Write-Host "  • Ou especifica portas para armadilhas personalizadas:"
Write-Host "    sentinela 22 80 443 3306 8080" -ForegroundColor Cyan
Write-Host "`nAtalhos uteis na TUI:"
Write-Host "  [K] Killswitch de Emergencia (Isolamento de Rede)"
Write-Host "  [W] Auditoria de Portas Abertas e Vulnerabilidades"
Write-Host "  [Q] Sair de forma segura`n"
