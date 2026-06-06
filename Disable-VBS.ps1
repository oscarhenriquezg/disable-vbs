#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detecta el estado de Virtualization-Based Security (VBS) en Windows 11 y lo deshabilita
    por la via correcta segun haya o no UEFI lock.

.DESCRIPTION
    A diferencia de los "trucos" tipicos de foro (desactivar Secure Boot a mano), este script:
      1. Verifica privilegios de administrador.
      2. Detecta el estado real de VBS / HVCI / Credential Guard via WMI (Win32_DeviceGuard).
      3. Detecta si VBS esta protegido con UEFI lock (no se puede quitar solo por registro).
      4. Comprueba Tamper Protection (bloquea cambios de registro en 24H2) y avisa.
      5. Hace BACKUP de las claves de registro antes de tocarlas (reversible).
      6. Aplica los cambios de registro correctos (set a 0, NO delete) + bcdedit.
      7. Reporta el resultado y recuerda el reinicio.

    Por defecto corre en modo -DryRun (solo muestra que haria). Pasa -Apply para ejecutar.

.PARAMETER Apply
    Aplica los cambios. Sin este switch, el script solo diagnostica (dry-run).

.PARAMETER BackupPath
    Carpeta donde guardar el backup .reg de las claves DeviceGuard/Lsa. Default: escritorio.

.EXAMPLE
    .\Disable-VBS.ps1
    # Solo diagnostica el estado actual, no cambia nada.

.EXAMPLE
    .\Disable-VBS.ps1 -Apply
    # Hace backup y deshabilita VBS (si no hay UEFI lock). Requiere reinicio.

.NOTES
    Autor: preparado para Oscar HG
    Requisitos: Ejecutar como Administrador. Windows 11 (22H2 / 23H2 / 24H2).
#>

[CmdletBinding()]
param(
    [switch]$Apply,
    [string]$BackupPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) "VBS-Backup")
)

$ErrorActionPreference = 'Stop'

# --- Helpers de salida -------------------------------------------------------
function Write-Section { param([string]$Text) Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Write-Ok      { param([string]$Text) Write-Host "[ OK ] $Text" -ForegroundColor Green }
function Write-Warn    { param([string]$Text) Write-Host "[WARN] $Text" -ForegroundColor Yellow }
function Write-Err     { param([string]$Text) Write-Host "[FAIL] $Text" -ForegroundColor Red }
function Write-Info    { param([string]$Text) Write-Host "[INFO] $Text" -ForegroundColor Gray }

# --- 1. Diagnostico de estado via WMI ---------------------------------------
function Get-VbsState {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

    # VirtualizationBasedSecurityStatus: 0=Off, 1=Enabled-not-running, 2=Running
    $vbsMap = @{ 0 = 'Deshabilitado'; 1 = 'Habilitado (no corriendo)'; 2 = 'Habilitado y CORRIENDO' }

    # SecurityServicesRunning: 1=Credential Guard, 2=HVCI/Memory Integrity, 3=System Guard...
    $svcMap = @{ 0 = 'Ninguno'; 1 = 'Credential Guard'; 2 = 'HVCI (Memory Integrity)'; 3 = 'System Guard Secure Launch'; 4 = 'SMM Firmware Measurement' }
    $running = @($dg.SecurityServicesRunning | ForEach-Object { $svcMap[[int]$_] })

    [PSCustomObject]@{
        VbsStatusCode  = [int]$dg.VirtualizationBasedSecurityStatus
        VbsStatusText  = $vbsMap[[int]$dg.VirtualizationBasedSecurityStatus]
        ServicesRunning= if ($running) { $running -join ', ' } else { 'Ninguno' }
        Raw            = $dg
    }
}

# --- 2. Deteccion de UEFI lock ----------------------------------------------
# Indicadores de que VBS/CG fue habilitado CON UEFI lock (no se puede quitar solo por registro).
function Test-UefiLock {
    $locked = $false
    $reasons = @()

    # Credential Guard con secreto root aislado presente => CG activo
    $cgSecret = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    if (Test-Path $cgSecret) {
        $p = Get-ItemProperty -Path $cgSecret -ErrorAction SilentlyContinue
        if ($p.PSObject.Properties.Name -contains 'IsolatedCredentialsRootSecret') {
            $reasons += 'Credential Guard con secreto aislado presente'
        }
    }

    # Flag "Locked" en el escenario HVCI
    $hvci = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
    if (Test-Path $hvci) {
        $p = Get-ItemProperty -Path $hvci -ErrorAction SilentlyContinue
        if ($p.Locked -eq 1) { $locked = $true; $reasons += 'HVCI Scenario Locked=1' }
    }

    # RequirePlatformSecurityFeatures via politica suele acompanar al UEFI lock
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    if (Test-Path $pol) {
        $p = Get-ItemProperty -Path $pol -ErrorAction SilentlyContinue
        if ($p.RequirePlatformSecurityFeatures) { $reasons += "Politica RequirePlatformSecurityFeatures=$($p.RequirePlatformSecurityFeatures)" }
    }

    [PSCustomObject]@{ Locked = $locked; Indicators = $reasons }
}

# --- 3. Tamper Protection (solo lectura; se apaga manual desde Windows Security) ---
function Test-TamperProtection {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
    if (Test-Path $path) {
        $p = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        return ($p.TamperProtection -eq 5)  # 5 = activado, 4 = desactivado
    }
    return $false
}

# --- 4. Backup de claves de registro afectadas ------------------------------
function Backup-Registry {
    param([string]$Dest)
    if (-not (Test-Path $Dest)) { New-Item -ItemType Directory -Path $Dest -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $targets = @(
        'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard',
        'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    )
    foreach ($t in $targets) {
        $safe = ($t -replace '[\\:]', '_')
        $file = Join-Path $Dest "$safe-$stamp.reg"
        # reg export falla silenciosamente si la clave no existe; lo ignoramos
        & reg.exe export $t $file /y *> $null
        if (Test-Path $file) { Write-Ok "Backup: $file" }
    }
}

# --- 5. Aplicar deshabilitacion (solo caso SIN UEFI lock) -------------------
function Set-RegDword {
    param([string]$Path, [string]$Name, [int]$Value)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    Write-Ok "$Path\$Name = $Value"
}

function Disable-VBS {
    Write-Section 'Aplicando cambios de registro (set a 0, NO delete)'

    # VBS core
    Set-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 0

    # HVCI / Memory Integrity
    Set-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 0

    # Credential Guard
    Set-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' 'Enabled' 0
    Set-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' 0

    # Politicas (si una GPO local las creo)
    Set-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity' 0
    Set-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'LsaCfgFlags' 0

    Write-Section 'Desactivando el hypervisor en el arranque (bcdedit)'
    & bcdedit.exe /set hypervisorlaunchtype off | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok 'bcdedit /set hypervisorlaunchtype off' }
    else { Write-Err 'bcdedit fallo (revisar Secure Boot / BitLocker)' }
}

# ============================== MAIN ========================================
Write-Section 'Estado actual de VBS'
$state = Get-VbsState
Write-Info "VBS: $($state.VbsStatusText)  (code $($state.VbsStatusCode))"
Write-Info "Servicios corriendo: $($state.ServicesRunning)"

if ($state.VbsStatusCode -eq 0) {
    Write-Ok 'VBS ya esta deshabilitado. No hay nada que hacer.'
    return
}

Write-Section 'Deteccion de UEFI lock'
$lock = Test-UefiLock
if ($lock.Locked) {
    Write-Warn 'VBS parece estar protegido con UEFI LOCK.'
    $lock.Indicators | ForEach-Object { Write-Info "  - $_" }
    Write-Host @"

  >> RUTA CORRECTA para UEFI lock (NO desactives Secure Boot a mano):
     1. Descarga la herramienta oficial 'Device Guard and Credential Guard
        hardware readiness tool' (dgreadiness_v3.6.zip) de Microsoft.
     2. Ejecuta en PowerShell admin:
            .\DG_Readiness_Tool_v3.6.ps1 -Disable
     3. Reinicia. En el arranque te pedira confirmar (tecla F3) desde la
        consola fisica para retirar el lock de VBS y Credential Guard.
     Esto quita el lock de forma limpia sin debilitar Secure Boot.

"@ -ForegroundColor Yellow
} else {
    Write-Ok 'Sin UEFI lock: se puede deshabilitar por registro + bcdedit.'
}

Write-Section 'Tamper Protection'
if (Test-TamperProtection) {
    Write-Warn 'Tamper Protection esta ACTIVADO. Revertira los cambios de registro.'
    Write-Host @"
  >> Apagalo ANTES de aplicar:
     Configuracion > Privacidad y seguridad > Seguridad de Windows >
     Proteccion antivirus y contra amenazas > Administrar la configuracion >
     Proteccion contra alteraciones -> Desactivar
  (No se puede apagar por script: es justamente lo que impide Tamper Protection.)
"@ -ForegroundColor Yellow
} else {
    Write-Ok 'Tamper Protection desactivado o no aplicable.'
}

# --- Decision de ejecucion ---
if (-not $Apply) {
    Write-Section 'MODO DIAGNOSTICO (dry-run)'
    Write-Info 'No se cambio nada. Para aplicar: .\Disable-VBS.ps1 -Apply'
    return
}

if ($lock.Locked) {
    Write-Err 'No aplico cambios automaticos: hay UEFI lock. Usa la herramienta oficial (ver arriba).'
    return
}

Write-Section 'Backup de registro'
Backup-Registry -Dest $BackupPath

Disable-VBS

Write-Section 'Verificacion'
$after = Get-VbsState
Write-Info "VBS ahora: $($after.VbsStatusText) (code $($after.VbsStatusCode))"
Write-Host @"

  Los cambios surten efecto tras REINICIAR.
  Despues del reinicio, verifica con:
      msinfo32   ->  'Seguridad basada en virtualizacion' debe decir 'No habilitada'
  o por PowerShell:
      (Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus
      # 0 = deshabilitado

  Para REVERTIR: importa el .reg de la carpeta de backup y ejecuta:
      bcdedit /set hypervisorlaunchtype auto

"@ -ForegroundColor Cyan
