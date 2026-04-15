// Destructive / defense-evasion LOLBin command strings embedded in a binary.
// Sigma catches these at process-launch time; this rule catches them when
// they're *baked into* a binary that hasn't run yet, or inside unpacked
// memory regions. Threshold 2-of-N because sysadmin scripts, backup tools,
// and even EDRs themselves reference one of these in isolation.
//
// Tier: signal-only — informational unless combined with other detections.

rule DefenseEvasion_DestructiveCmdlineStrings
{
    meta:
        description = "Embedded command strings for shadow-copy deletion, log clearing, recovery tampering, or firewall/boot disablement"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Shadow copy / backup destruction
        $s01 = "vssadmin delete shadows"        ascii nocase
        $s02 = "vssadmin delete shadows"        wide  nocase
        $s03 = "wbadmin delete catalog"         ascii nocase
        $s04 = "wbadmin delete catalog"         wide  nocase
        $s05 = "wbadmin delete backup"          ascii nocase
        $s06 = "wbadmin delete systemstatebackup" ascii nocase
        $s07 = "wmic shadowcopy delete"         ascii nocase
        $s08 = "wmic shadowcopy delete"         wide  nocase
        $s09 = "DeleteShadowStorage"            ascii nocase

        // Event log tampering
        $s10 = "wevtutil cl "                   ascii nocase
        $s11 = "wevtutil cl "                   wide  nocase
        $s12 = "wevtutil clear-log"             ascii nocase
        $s13 = "Clear-EventLog"                 ascii nocase
        $s14 = "fsutil usn deletejournal"       ascii nocase
        $s15 = "fsutil usn deletejournal"       wide  nocase

        // Boot / recovery tampering
        $s16 = "bcdedit /set"                   ascii nocase
        $s17 = "bcdedit /set"                   wide  nocase
        $s18 = "recoveryenabled no"             ascii nocase
        $s19 = "bootstatuspolicy ignoreallfailures" ascii nocase
        $s20 = "bcdedit /deletevalue"           ascii nocase

        // Anti-forensics / drive wiping
        $s21 = "cipher /w:"                     ascii nocase
        $s22 = "cipher /w:"                     wide  nocase
        $s23 = "format C: /y"                   ascii nocase
        $s24 = "SDelete"                        ascii
        $s25 = "diskshadow.exe"                 ascii nocase

        // Defender tampering
        $s26 = "Set-MpPreference -Disable"      ascii nocase
        $s27 = "Uninstall-WindowsFeature Windows-Defender" ascii nocase
        $s28 = "Add-MpPreference -ExclusionPath" ascii nocase

        // Firewall / service disablement
        $s29 = "netsh advfirewall set allprofiles state off" ascii nocase
        $s30 = "netsh advfirewall set allprofiles state off" wide  nocase
        $s31 = "sc stop WinDefend"              ascii nocase
        $s32 = "sc config "                     ascii nocase

        // Self-deletion pattern ("ping -n x & del")
        $s33 = "choice /C Y /N /D Y /T"         ascii nocase
        $s34 = "ping -n 1 127.0.0.1 & del"      ascii nocase
        $s35 = "& del %~f0"                     ascii nocase

    condition:
        2 of them
}
