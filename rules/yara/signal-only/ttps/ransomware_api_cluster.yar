// Ransomware-shaped API/string cluster. A single import or string from this
// set is meaningless — the combination is the signal. Threshold is 3-of-5
// categories to keep FP rate down on legitimate backup/crypto tools.
//
// Tier: signal-only (never auto-quarantines — rule exists to surface the
// fingerprint alongside other detections, not to block by itself).

rule Ransomware_ApiCluster_Generic
{
    meta:
        description = "Binary exhibits the import/string cluster typical of ransomware: crypto + file-enumeration + shadow-copy-deletion + boot-tampering + extension-rename"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // --- Crypto APIs ---
        $crypto_bcrypt    = "BCryptEncrypt"        ascii
        $crypto_crypt     = "CryptEncrypt"         ascii
        $crypto_genkey    = "CryptGenKey"          ascii
        $crypto_derivekey = "BCryptDeriveKey"      ascii
        $crypto_import    = "CryptImportKey"       ascii
        $crypto_rsa       = "RSA_OAEP"             ascii
        $crypto_curve     = "Curve25519"           ascii

        // --- File enumeration ---
        $enum_firstw      = "FindFirstFileW"       ascii
        $enum_nextw       = "FindNextFileW"        ascii
        $enum_firsta      = "FindFirstFileA"       ascii
        $enum_nexta       = "FindNextFileA"        ascii
        $enum_drives      = "GetLogicalDriveStringsW" ascii
        $enum_netres      = "WNetEnumResourceW"    ascii

        // --- Shadow copy / backup destruction ---
        $shadow_vssadmin  = "vssadmin delete shadows"          ascii nocase
        $shadow_vssadminw = "vssadmin delete shadows"          wide  nocase
        $shadow_wbadmin   = "wbadmin delete catalog"           ascii nocase
        $shadow_wbadminw  = "wbadmin delete catalog"           wide  nocase
        $shadow_wmic      = "wmic shadowcopy delete"           ascii nocase
        $shadow_wmicw     = "wmic shadowcopy delete"           wide  nocase
        $shadow_diskshad  = "diskshadow"                       ascii nocase
        $shadow_com       = "Win32_ShadowCopy"                 ascii
        $shadow_comw      = "Win32_ShadowCopy"                 wide

        // --- Boot-recovery tampering (Windows Recovery Environment, BCD) ---
        $boot_bcd_set     = "bcdedit /set"                     ascii nocase
        $boot_bcd_setw    = "bcdedit /set"                     wide  nocase
        $boot_ignorefail  = "bootstatuspolicy ignoreallfailures" ascii nocase
        $boot_ignorefailw = "bootstatuspolicy ignoreallfailures" wide  nocase
        $boot_recovery_no = "recoveryenabled no"               ascii nocase
        $boot_recovery_nw = "recoveryenabled no"               wide  nocase
        $boot_safeboot    = "bcdedit /deletevalue {default} safeboot" ascii nocase

        // --- Extension rename / ransom markers ---
        $ext_encrypted    = ".encrypted"                       ascii
        $ext_locked       = ".locked"                          ascii
        $ext_crypt        = ".crypt"                           ascii
        $ext_paying       = ".pay2key"                         ascii
        $ext_fmt          = ".%s"                              ascii  // rename template
        $ext_tpl_cat      = "%s%s%s.%s"                        ascii  // path-concat rename template
        $note_extension   = "_readme.txt"                      ascii  nocase

    condition:
        // Require signal from 3 distinct categories — a generic crypto library
        // alone shouldn't fire, nor should a backup utility, nor a disk tool.
        // YARA can't nest `of` groups, so we coerce each category to 0/1.
        (
            (any of ($crypto_*) ? 1 : 0) +
            (2 of ($enum_*)     ? 1 : 0) +
            (any of ($shadow_*) ? 1 : 0) +
            (any of ($boot_*)   ? 1 : 0) +
            (any of ($ext_*) or $note_extension ? 1 : 0)
        ) >= 3
}
