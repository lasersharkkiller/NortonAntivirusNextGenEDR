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

# SIG # Begin signature block
# MIIZPQYJKoZIhvcNAQcCoIIZLjCCGSoCAQExDzANBglghkgBZQMEAgIFADCBiQYK
# KwYBBAGCNwIBBKB7MHkwNAYKKwYBBAGCNwIBHjAmAgMBAAAEEB/MO2BZSwhOtyTS
# xil+81ECAQACAQACAQACAQACAQAwQTANBglghkgBZQMEAgIFAAQwf2gPL26wXti8
# sUauTlxgOuVu4yNb2yxAMk0HdwR5x2J38yrOWG07k4/sqNYUHISgoIIHqzCCA4Iw
# ggMJoAMCAQICEG7dTyXnMX05gVcxNM/B3KAwCgYIKoZIzj0EAwMwfzELMAkGA1UE
# BhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQK
# DA9TU0wgQ29ycG9yYXRpb24xNDAyBgNVBAMMK1NTTC5jb20gRVYgUm9vdCBDZXJ0
# aWZpY2F0aW9uIEF1dGhvcml0eSBFQ0MwHhcNMTkwMzA3MTkzNzQ1WhcNMzQwMzAz
# MTkzNzQ1WjB7MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcM
# B0hvdXN0b24xETAPBgNVBAoMCFNTTCBDb3JwMTcwNQYDVQQDDC5TU0wuY29tIEVW
# IENvZGUgU2lnbmluZyBJbnRlcm1lZGlhdGUgQ0EgRUNDIFIyMHYwEAYHKoZIzj0C
# AQYFK4EEACIDYgAEOtDh2pPivFbRSTS4gSw0RNIbJZOisv9PtOQfM8Em+0x6QIba
# 7OVUb+iRc1OQKYpuBdHutw64OyAJ6GOMoFGgFPsW4zIrjkKkQUB7UOqilud5eINc
# sBnMvw4joLPlFKmxo4IBTDCCAUgwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSME
# GDAWgBRbyl7l3tKBqs2oLWRRttlym5fmTzB7BggrBgEFBQcBAQRvMG0wSQYIKwYB
# BQUHMAKGPWh0dHA6Ly93d3cuc3NsLmNvbS9yZXBvc2l0b3J5L1NTTGNvbS1Sb290
# Q0EtRVYtRUNDLTM4NC1SMS5jcnQwIAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3Nwcy5z
# c2wuY29tMBEGA1UdIAQKMAgwBgYEVR0gADATBgNVHSUEDDAKBggrBgEFBQcDAzA9
# BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY3Jscy5zc2wuY29tL3NzbC5jb20tRVZl
# Y2MtUm9vdENBLmNybDAdBgNVHQ4EFgQUAYmUuf60M13w8fqF+SRGhKNXaV4wDgYD
# VR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2cAMGQCMEpb6oCfujaSz4wx7eylme4y
# J7zDF+uHj1dQMAW/dZX3PPk/GVKDNCDhEVbuOT637gIwArW42fh4EkfBwEX/Ffag
# ZrtD4k9DDlh3l6SiVTQkhFpWGc+mVSAb2RCaUwD7iV5wMIIEITCCA6egAwIBAgIQ
# GJjU5pBpDM/lrusj9A3NkTAKBggqhkjOPQQDAzB7MQswCQYDVQQGEwJVUzEOMAwG
# A1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xETAPBgNVBAoMCFNTTCBDb3Jw
# MTcwNQYDVQQDDC5TU0wuY29tIEVWIENvZGUgU2lnbmluZyBJbnRlcm1lZGlhdGUg
# Q0EgRUNDIFIyMB4XDTI2MDYyMzE4MjgyNloXDTI3MDkyNDE4MjgyNlowgdAxCzAJ
# BgNVBAYTAlVTMRAwDgYDVQQIDAdHZW9yZ2lhMRAwDgYDVQQHDAdBdGxhbnRhMR0w
# GwYDVQQKDBRNYWNhcm9uaSBSb2NrZXRzIExMQzERMA8GA1UEBRMIMjYwODQ3MzUx
# HTAbBgNVBAMMFE1hY2Fyb25pIFJvY2tldHMgTExDMR0wGwYDVQQPDBRQcml2YXRl
# IE9yZ2FuaXphdGlvbjEYMBYGCysGAQQBgjc8AgECDAdHZW9yZ2lhMRMwEQYLKwYB
# BAGCNzwCAQMTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE1mCU9/DfxVIy6hTP
# N3Aa3IMb8bPe/suHtpOtLhDIlybm7oSyX8KKyaVtHaRpMdaXLfdVcmSUT4LbPCHh
# 2rG8WJMlLENDoeE9WG6vD9Z0TJBlg2uFP6X7+wfFHN29P2Ndo4IBmDCCAZQwDAYD
# VR0TAQH/BAIwADAfBgNVHSMEGDAWgBQBiZS5/rQzXfDx+oX5JEaEo1dpXjB8Bggr
# BgEFBQcBAQRwMG4wSgYIKwYBBQUHMAKGPmh0dHA6Ly9jZXJ0LnNzbC5jb20vU1NM
# Y29tLVN1YkNBLUVWLWNvZGVTaWduaW5nLUVDQy0zODQtUjIuY2VyMCAGCCsGAQUF
# BzABhhRodHRwOi8vb2NzcHMuc3NsLmNvbTBQBgNVHSAESTBHMAcGBWeBDAEDMDwG
# DCsGAQQBgqkwAQMDAjAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5zc2wuY29t
# L3JlcG9zaXRvcnkwEwYDVR0lBAwwCgYIKwYBBQUHAwMwTwYDVR0fBEgwRjBEoEKg
# QIY+aHR0cDovL2NybHMuc3NsLmNvbS9TU0xjb20tU3ViQ0EtRVYtY29kZVNpZ25p
# bmctRUNDLTM4NC1SMi5jcmwwHQYDVR0OBBYEFCGf1ay4z9sF9eNXOjyi37YAZJY5
# MA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAwNoADBlAjEA0dvY3NLvoU+Jv1Jl
# Xra8bP4tHi/FjGowvwm99wqNX3DwHtn6/05Aj3XKQbxUk299AjANrsfElLAtXD4s
# m1QCHQodW8mkN3jhUoiz9BLOfuK9umGNnFzTbG9RHX2grd56tYUxghDXMIIQ0wIB
# ATCBjzB7MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hv
# dXN0b24xETAPBgNVBAoMCFNTTCBDb3JwMTcwNQYDVQQDDC5TU0wuY29tIEVWIENv
# ZGUgU2lnbmluZyBJbnRlcm1lZGlhdGUgQ0EgRUNDIFIyAhAYmNTmkGkMz+Wu6yP0
# Dc2RMA0GCWCGSAFlAwQCAgUAoIGMMBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3
# DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEV
# MD8GCSqGSIb3DQEJBDEyBDAE5/LrSWpWnQciQ8ik5t3wH3CW0A3iEy6REGpgpT0+
# BEnlgnuXGm/WMvZV9rCUEMMwCwYHKoZIzj0CAQUABGYwZAIwJk08M77krl4IB7g9
# emGFG/NZiXmqzS5a8mqWFS2YApU8bOCKRATbWoWmlf9q66vFAjB/biFhHMCF1mZE
# W7rVVxr5vSMtAGar2XkUKm8HHcPKNVO/kgDLCut5daFLrNL6K/+hgg8nMIIPIwYK
# KwYBBAGCNwMDATGCDxMwgg8PBgkqhkiG9w0BBwKggg8AMIIO/AIBAzENMAsGCWCG
# SAFlAwQCATCBhwYLKoZIhvcNAQkQAQSgeAR2MHQCAQEGDCsGAQQBgqkwAQMGATBB
# MA0GCWCGSAFlAwQCAgUABDAKJW4h7aOAKeEsDozECVbCdATAeFzsiVb4eW8uEvAl
# Am+nMe/Z2eOUuiQPYSpkSicCCDPi6SvC0i9UGA8yMDI2MDYyNjAxMTIyM1owAwIB
# AaCCDAAwggT8MIIC5KADAgECAhAfaxZi0i4bbF3xwMGgYA44MA0GCSqGSIb3DQEB
# CwUAMHMxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91
# c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLzAtBgNVBAMMJlNTTC5jb20gVGltZXN0
# YW1waW5nIElzc3VpbmcgUlNBIENBIFIxMB4XDTI1MDIxODE2MzIwMloXDTM0MTEx
# MjE4NTAwNVowbjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQH
# DAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEqMCgGA1UEAwwhU1NMLmNvbSBU
# aW1lc3RhbXBpbmcgVW5pdCAyMDI1IEUxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
# QgAEG/tRUcdv5lWW7E9eV8Tczq2DReerx2Jz47e884JGlqVQzW870D4ZHNJVWPLK
# AeFisHDrZcsWHWS/t77JF39pNqOCAVowggFWMB8GA1UdIwQYMBaAFAydECWOmqcb
# mYdDzwh+4b2BkPTPMFEGCCsGAQUFBwEBBEUwQzBBBggrBgEFBQcwAoY1aHR0cDov
# L2NlcnQuc3NsLmNvbS9TU0wuY29tLXRpbWVTdGFtcGluZy1JLVJTQS1SMS5jZXIw
# UQYDVR0gBEowSDA8BgwrBgEEAYKpMAEDBgEwLDAqBggrBgEFBQcCARYeaHR0cHM6
# Ly93d3cuc3NsLmNvbS9yZXBvc2l0b3J5MAgGBmeBDAEEAjAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDBGBgNVHR8EPzA9MDugOaA3hjVodHRwOi8vY3Jscy5zc2wuY29t
# L1NTTC5jb20tdGltZVN0YW1waW5nLUktUlNBLVIxLmNybDAdBgNVHQ4EFgQUznzZ
# wASAxSQQagnqHKslPRH9qNIwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUA
# A4ICAQCAc3Ukhb1mU2KnTsV9j2vUsnAspOXWH/L2vUGMOAcwTPtTsnuYDLfYnEDU
# ovKMIImo2S5F+EMcYUR9m2NM6u7sBAwNIOJQO8IJzeNrPmnL2Ma/Ah7memQttepe
# ED5KoLMbvX1RKKDCEeRivu/w2JehpjRe7TenQGJlmt5mWmeCYYH37zo33gWogXHY
# jlnmK67t3iPtoA5kE3F9T2MUMggYO1Z9Z4KkXRDyssT/cMcOXMkqzkiXeL9Wg6Xu
# tNT3fyhKvEzDDDoYMGUpfysYfG+SOAhv0xeRWCUlIMew0BkN4JL+KdrEocD4KG4H
# wrg7EjFrqTV754cHKlqQBjfC43vDs+U+aE3qTkh2pmfcdkezZWOhHzjVn3CZU8V0
# YN2QFntc6Zvk5lRoq5+y+0RHRVtjYOTNqoBoi23WRz4j4VTPs+JXPY9TOl6CR+1F
# HG+s/IgvTxuUlOdsxDReuoM3SsR+5Mu/heGGcrIlpeHEJR2M79xG6YzNnflBNQwi
# 0FbLXEanSLKgVWcDJrak+xUy4Aj6zLXPGU5L2XmJLG8onyCmek6COphNru7V7Jmj
# 7gmVwaiKJHXsu2ExOsXWrra07nE6kjy3FRnqC0oa2QlXrB2P69ktzApnYz3capWk
# 6jpQGUaPHWwqxVnsAhTMlmWLg0nQzYphyt82eV5uRgqkOdKpbDCCBvwwggTkoAMC
# AQICEG1SGHCH6CNNhWAA0ICPk1YwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQKDA9T
# U0wgQ29ycG9yYXRpb24xMTAvBgNVBAMMKFNTTC5jb20gUm9vdCBDZXJ0aWZpY2F0
# aW9uIEF1dGhvcml0eSBSU0EwHhcNMTkxMTEzMTg1MDA1WhcNMzQxMTEyMTg1MDA1
# WjBzMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0
# b24xETAPBgNVBAoMCFNTTCBDb3JwMS8wLQYDVQQDDCZTU0wuY29tIFRpbWVzdGFt
# cGluZyBJc3N1aW5nIFJTQSBDQSBSMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAK5REBPS+TwgoCCF3slQHGTJ4f3F6TT/Cn8xSOhyWsVeqGH98Yf3UVz7
# t+bQwcITsD7CY6KoGP04OskBgareubfeMKcdKwIE1YBBjKhq4urwiOqxLUmVcvb2
# oM0wx3BnxQ3NBLu9ZkwMnjQlIY2mEwZMgDaqfZuiEa2BFzinXf3kRLKlQ5oa8ne3
# QU0vcG4qZvphy0xxBQXayqigzN3z2HQTq6N28EOjpnA2dajGPtiZ9aNJeDfcDka5
# j3KbhBkzk4RWCjx5vP8H6DKHIIs02GHgxv/jG8JMIxWY1isG+IaB09livKbxlvzh
# NAKZK5fQmUstrpYrVo7qqXAhJtv1tUaHzrp6QpuUL9dE/bSAC7UKO9xhyJSA1OsY
# WDx/wAmBA84JzX8IJ1olJjCEmlJ2F4o6dCARKA2Zhk+EU4LogpowBReTlTW2NNwU
# KAW+8Cte0rhrMBZQ47Vjd92V0gEvouOTMtQJgk2QVeqGwFVw8y4HSdQNa8sl8+Ka
# y2MnyUXhLoQLFaeVaLs4SVXBOe3Ua1Gp5j3J2+8Yue1T4V5wrsNuocNR3frpSt4y
# RIG3N68Bz1qqhk+eNUyO8WpXWlg6POZOJUdm0BzzRsB8V7kst8nM8joOe03Kqhun
# BN69Ckeo8M32qo07zeveRrDwD2P4dmJLDYBflwZ1A/SQbS+HN+AHAgMBAAGjggGB
# MIIBfTASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFN0ECQei9Xp9UlMS
# kpXuOIAlDaZZMIGDBggrBgEFBQcBAQR3MHUwUQYIKwYBBQUHMAKGRWh0dHA6Ly93
# d3cuc3NsLmNvbS9yZXBvc2l0b3J5L1NTTGNvbVJvb3RDZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5UlNBLmNydDAgBggrBgEFBQcwAYYUaHR0cDovL29jc3BzLnNzbC5jb20w
# PwYDVR0gBDgwNjA0BgRVHSAAMCwwKgYIKwYBBQUHAgEWHmh0dHBzOi8vd3d3LnNz
# bC5jb20vcmVwb3NpdG9yeTATBgNVHSUEDDAKBggrBgEFBQcDCDA7BgNVHR8ENDAy
# MDCgLqAshipodHRwOi8vY3Jscy5zc2wuY29tL3NzbC5jb20tcnNhLVJvb3RDQS5j
# cmwwHQYDVR0OBBYEFAydECWOmqcbmYdDzwh+4b2BkPTPMA4GA1UdDwEB/wQEAwIB
# hjANBgkqhkiG9w0BAQsFAAOCAgEAkhl1DaZaQs8ZB9ny/JT6wJvwFelEllovcTPd
# UOUTe5mTdw/E+3JtV8u6ppyLRbpIHbYlMy20KJAychU6xdaci4BsP9oVNxSRMsEj
# fHKz7ARqPNdpclhYAINLjsFGMO1iUNbXiAsnF/xboNCgfeMcMYbLyQYkU6UMobv9
# isrtQZ8e0EAQNV7qXJn4W0KyuTt0P8iIv/5DdDpIUBIktDZcjz2KEW6B1gvvsKIM
# 1esjYwWylAazBcQAake5pANMdSn8t1HdPKsiwuWfOguyRQazAX8oXz6SlZSIok0L
# is9a02vGVtdhEaB0R3HxIyNRMMKWV1yuSeUXFuoexWav3GRPZC0WYb50SrW/l+wg
# rS8doetaMwyZon2L7ioYlIPSy1h9Dq/Q911PsSkbEZ3zrsB1roVnIfBu5BJp0xvQ
# rQ/Q4LavuvCoFR7QFoypNrotbNYi2AGMZw5td4zGZtCqUTPZi0BwSuRm+HRYAEMM
# ThTwbJX/fYV1oC8mBN970yIvadIGKhh7+DmYdRJYBrL8inVFCZAK+YX2w1+qWEnC
# SPL/VTWJtSRMhQFfceDKbJC+pBNksvKzqkva0J1ZyMj1i4vDfSuBmbz4rfzsvvJx
# S+quZDdkmW6MeXevWGBXvqzdbAw+AqTVsAQUyP6tFeKZIL4S/fSFdl2rIx2X+KXk
# qx3S+EYxggJYMIICVAIBATCBhzBzMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4
# YXMxEDAOBgNVBAcMB0hvdXN0b24xETAPBgNVBAoMCFNTTCBDb3JwMS8wLQYDVQQD
# DCZTU0wuY29tIFRpbWVzdGFtcGluZyBJc3N1aW5nIFJTQSBDQSBSMQIQH2sWYtIu
# G2xd8cDBoGAOODALBglghkgBZQMEAgGgggFhMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjYwNjI2MDExMjIzWjAoBgkqhkiG9w0B
# CTQxGzAZMAsGCWCGSAFlAwQCAaEKBggqhkjOPQQDAjAvBgkqhkiG9w0BCQQxIgQg
# r8IlRJADob7LickseGJvJLBzGU33YbI9WmWcpUuZXVUwgckGCyqGSIb3DQEJEAIv
# MYG5MIG2MIGzMIGwBCBUKvmhao1yLmYRSXiK6ZTBipqu5aZcs0SiVJr5bHnHizCB
# izB3pHUwczELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdI
# b3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEvMC0GA1UEAwwmU1NMLmNvbSBUaW1l
# c3RhbXBpbmcgSXNzdWluZyBSU0EgQ0EgUjECEB9rFmLSLhtsXfHAwaBgDjgwCgYI
# KoZIzj0EAwIERzBFAiEAs+kL84/pjE/X1HN8bi+DHqt5IEM+lqSxf40M8Li5LUQC
# IHyxGJ0Zu9iegHeAabjZGNMXH2YNBXHREgWRvO5n44hf
# SIG # End signature block
