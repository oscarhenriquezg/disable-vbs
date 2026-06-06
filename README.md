# Disable-VBS

Detecta y deshabilita **Virtualization-Based Security (VBS)** en Windows 11 por la vía
correcta según el equipo tenga o no **UEFI lock** — en lugar de los típicos "trucos" de
foro que recomiendan desactivar Secure Boot a mano.
 
VBS y Credential Guard se habilitan **por defecto** desde Windows 11 22H2 en hardware
compatible. En la mayoría de los casos eso se hace **sin UEFI lock**, por lo que basta con
registro + `bcdedit`. Este script lo detecta primero y solo entonces decide qué hacer.
 
---
 
## ¿Por qué este script?
 
La mayoría de las guías fallan o son peligrosas porque ignoran tres puntos:
 
1. **No distinguen si hay UEFI lock.** Si VBS se habilitó con lock, ningún cambio de
   registro lo apaga; hay que retirarlo con la herramienta oficial de Microsoft (no
   desactivando Secure Boot, que debilita el arranque).
2. **Tamper Protection (Windows 11 24H2)** revierte los cambios de registro. Si no lo
   apagas antes, "no funciona" y nadie te dice por qué.
3. **Borran las claves** de Credential Guard en vez de ponerlas a `0`, lo que a veces no
   deshabilita nada.
Este script resuelve los tres.
 
---
 
## Características
 
- **Modo diagnóstico por defecto** (dry-run): no cambia nada salvo que pases `-Apply`.
- Lee el estado real vía WMI (`Win32_DeviceGuard`), la misma fuente que `msinfo32`.
- **Detecta UEFI lock** mediante tres indicadores (secreto aislado de Credential Guard,
  flag `Locked` de HVCI, política `RequirePlatformSecurityFeatures`).
- **Detecta Tamper Protection** y te da la ruta manual para apagarlo.
- **Hace backup `.reg`** de las claves afectadas antes de modificar (reversible).
- Setea valores a `0` (no borra claves).
- Verifica el resultado y deja las instrucciones de reversión.
---
 
## Requisitos
 
- Windows 11 (22H2 / 23H2 / 24H2).
- PowerShell ejecutado **como Administrador**.
- Política de ejecución que permita el script (ver más abajo).
---
 
## Uso
 
### 1. Diagnóstico (no cambia nada)
 
```powershell
.\Disable-VBS.ps1
```
 
Muestra el estado de VBS, si hay UEFI lock y si Tamper Protection está activo.
 
### 2. Aplicar (deshabilita VBS)
 
```powershell
.\Disable-VBS.ps1 -Apply
```
 
Hace backup, aplica los cambios y pide reinicio. Solo procede si **no** hay UEFI lock.
 
### 3. Backup en una ruta específica
 
```powershell
.\Disable-VBS.ps1 -Apply -BackupPath "C:\Backups\VBS"
```
 
### Si la política de ejecución bloquea el script
 
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```
 
---
 
## Cómo decide
 
```
Estado VBS (WMI)
   ├── ya deshabilitado ──────────────► termina, nada que hacer
   └── habilitado
         ├── ¿UEFI lock?
         │     ├── SÍ ► NO toca registro. Indica usar DG_Readiness_Tool -Disable
         │     │        (confirmación F3 en el arranque). No desactiva Secure Boot.
         │     └── NO ► continúa
         ├── ¿Tamper Protection ON? ► avisa: apagarlo manualmente antes
         └── -Apply ► backup .reg → registro a 0 → bcdedit off → verifica
```
 
### Claves que modifica (caso sin UEFI lock)
 
| Clave | Valor | Efecto |
|---|---|---|
| `HKLM\...\Control\DeviceGuard\EnableVirtualizationBasedSecurity` | `0` | VBS off |
| `HKLM\...\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled` | `0` | HVCI / Memory Integrity off |
| `HKLM\...\DeviceGuard\Scenarios\CredentialGuard\Enabled` | `0` | Credential Guard off |
| `HKLM\...\Control\Lsa\LsaCfgFlags` | `0` | Credential Guard off (LSA) |
| `HKLM\SOFTWARE\Policies\...\DeviceGuard\*` | `0` | Anula políticas locales |
| `bcdedit /set hypervisorlaunchtype` | `off` | Desactiva el hypervisor en el arranque |
 
---
 
## Caso con UEFI lock
 
El script **no** lo fuerza. La vía correcta es la herramienta oficial de Microsoft:
 
1. Descarga `dgreadiness_v3.6.zip` (Device Guard and Credential Guard hardware readiness tool).
2. Ejecuta en PowerShell admin:
   ```powershell
   .\DG_Readiness_Tool_v3.6.ps1 -Disable
   ```
3. Reinicia. En el arranque te pedirá confirmar con **F3** desde la consola física, una vez
   para Credential Guard y otra para VBS. Esto retira el lock sin tocar Secure Boot.
---
 
## Advertencias
 
- **BitLocker:** modificar el arranque puede pedir la clave de recuperación en el próximo
  boot. Tenla a mano.
- **`hypervisorlaunchtype off` mata todo el hypervisor:** se caen Hyper-V, WSL2, Docker
  Desktop (backend WSL2) y Windows Sandbox. Si necesitas VBS off pero conservar Hyper-V,
  ese es otro escenario más complejo no cubierto aquí.
- **Requiere reinicio** para surtir efecto.
- VBS es una capa de seguridad real (aísla credenciales y refuerza la integridad de código).
  Deshabilitarlo tiene sentido para rendimiento, emuladores o virtualización anidada, pero
  es una decisión consciente, no un default recomendado.
---
 
## Verificación
 
Tras reiniciar:
 
```powershell
(Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus
# 0 = deshabilitado
```
 
O abre `msinfo32` → *Seguridad basada en virtualización* debe decir **No habilitada**.
 
---
 
## Reversión
 
1. Reimporta el `.reg` de la carpeta de backup (por defecto en el Escritorio, `VBS-Backup`).
2. Reactiva el hypervisor:
   ```powershell
   bcdedit /set hypervisorlaunchtype auto
   ```
3. Reinicia.
---
 
## Despliegue en flota
 
Para muchos equipos, **no uses este script por máquina**. Es más limpio y centralizado:
 
- **GPO / Intune:** `Computer Configuration > Administrative Templates > System > Device Guard
  > Turn On Virtualization Based Security = Disabled`.
- Evita además el problema de Tamper Protection por equipo.
Este script está pensado para diagnóstico y casos puntuales.
 
---
 
## Licencia
 
MIT. Úsalo bajo tu propia responsabilidad: modifica configuración de seguridad del sistema.
