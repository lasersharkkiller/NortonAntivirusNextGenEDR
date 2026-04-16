// Base64-wrapped payload detection. YARA's `base64` string modifier generates
// all three offset-aligned encodings of the literal at compile time, so a
// match fires regardless of where the string starts inside the blob (the
// classic problem that makes naive base64 matching miss 2/3 of cases).
//
// Tier: signal-only — base64 is legitimate content in certs, emails, JWTs,
// docx/pptx, git archive files, sourcemaps, etc. Combine with path / parent
// context before action.

// ---------------------------------------------------------------------------
// PE dropped inside a base64 blob — .ps1 / .hta / .js / .bat that carries an
// MZ executable embedded as base64 (classic in-memory-reflective-loader
// staging).
// ---------------------------------------------------------------------------
rule Base64_Embedded_PE_In_Script
{
    meta:
        description = "Script or document contains base64-encoded 'MZ…This program cannot be run' — embedded PE staged for in-memory load"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // DOS stub string that's present in every Microsoft linker PE
        // header, encoded as base64 (YARA emits 3 offset variants)
        $pe_dos = "This program cannot be run in DOS mode" base64 base64wide

        // "MZ\x90\x00" + Rich header lead — stable opening of an MZ image,
        // matched base64-aligned
        $mz_rich = { 4D 5A 90 00 03 00 00 00 } base64

        // PE signature suffix (appears ~0xC8 bytes in)
        $pe_sig  = "PE\x00\x00\x64\x86" base64

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// PowerShell IEX / download-exec strings encoded as base64 — catches
// `powershell -EncodedCommand <blob>` where the blob is UTF-16 PS source, and
// scripted re-encode chains where the inner script was base64'd to defeat
// string-match AV.
// ---------------------------------------------------------------------------
rule Base64_PowerShell_IngressExec_Markers
{
    meta:
        description = "Base64-encoded PowerShell ingress-exec markers (DownloadString/IEX/Invoke-Expression/New-Object Net.WebClient)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $dl_string  = "DownloadString(" base64 base64wide
        $dl_data    = "DownloadData("   base64 base64wide
        $iex        = "Invoke-Expression" base64 base64wide
        $webclient  = "Net.WebClient"    base64 base64wide
        $webreq     = "Invoke-WebRequest" base64 base64wide
        $asm_load   = "Reflection.Assembly" base64 base64wide
        $iex_short  = "| IEX"           base64 base64wide
        $iex_short2 = " |iex"           base64 base64wide
        $ast        = "AmsiScanBuffer"  base64 base64wide
        $bypass     = "amsiInitFailed"  base64 base64wide
        $amsi_utils = "AmsiUtils"       base64 base64wide

    condition:
        2 of them
}


// ---------------------------------------------------------------------------
// Mimikatz / Kerberos credential-theft command strings encoded as base64 —
// common when a C2 operator tasks a PowerShell agent with Invoke-Mimikatz via
// a base64-wrapped -Command payload.
// ---------------------------------------------------------------------------
rule Base64_Mimikatz_Kerberos_Cmdstrings
{
    meta:
        description = "Base64-wrapped Mimikatz / Kerberos command strings (sekurlsa / kerberos / lsadump / privilege::debug)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $m1 = "sekurlsa::logonpasswords" base64 base64wide
        $m2 = "sekurlsa::wdigest"        base64 base64wide
        $m3 = "kerberos::ptt"            base64 base64wide
        $m4 = "kerberos::golden"         base64 base64wide
        $m5 = "kerberos::silver"         base64 base64wide
        $m6 = "lsadump::sam"             base64 base64wide
        $m7 = "lsadump::dcsync"          base64 base64wide
        $m8 = "privilege::debug"         base64 base64wide
        $m9 = "token::elevate"           base64 base64wide
        $ma = "Invoke-Mimikatz"          base64 base64wide

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// Shellcode / syscall stub markers inside base64 blobs. Catches stagers that
// store the first-stage shellcode as base64 in a variable assignment, and
// docx/xlsm droppers that unpack shellcode from a custom XML part.
// ---------------------------------------------------------------------------
rule Base64_Shellcode_Syscall_Stub
{
    meta:
        description = "Base64-wrapped x64 direct-syscall stub (4C 8B D1 B8 ?? ?? 00 00 0F 05 C3)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // The syscall stub with SSN byte wildcarded, encoded aligned-at-0
        $stub = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 } base64
        // Common shellcode prologue: nop-sled run followed by call $+5
        $nopcall = { 90 90 90 90 90 90 E8 00 00 00 00 } base64

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// URL-safe base64 (RFC 4648 §5) blobs containing known tool tokens. URL-safe
// alphabet (`-`, `_`) is used by JWTs, OAuth flows, Cobalt Strike HTTPS
// profiles, and offensive frameworks that want to embed payloads in URLs or
// DNS labels. YARA's `base64` modifier emits the `+`/`/` form; we add
// explicit literals for the URL-safe form to cover both.
// ---------------------------------------------------------------------------
rule Base64_UrlSafe_Offensive_Tokens
{
    meta:
        description = "URL-safe-base64-encoded offensive tool tokens (mimikatz, rubeus, amsibypass) — alphabet uses '-' and '_'"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // The below would be generated from the standard encoder and then
        // have +/= replaced with -_ (URL-safe). We include representative
        // substrings of the URL-safe output as literals so the rule matches
        // without a full pre-computed alphabet mapping.

        // "mimikatz" standard-b64 prefix: "bWlta2F0eg" (no '+' or '/')
        $m_mimikatz = "bWlta2F0eg"           ascii

        // "Rubeus.Commands" → "UnViZXVzLkNvbW1hbmRz" (alphabet-safe)
        $m_rubeus   = "UnViZXVzLkNvbW1hbmRz" ascii

        // "AmsiScanBuffer" → "QW1zaVNjYW5CdWZmZXI"
        $m_amsi     = "QW1zaVNjYW5CdWZmZXI"  ascii

        // "powershell -nop -w hidden" → "cG93ZXJzaGVsbCAtbm9wIC13IGhpZGRlbg"
        $m_ps       = "cG93ZXJzaGVsbCAtbm9wIC13IGhpZGRlbg" ascii

        // "Invoke-Mimikatz" → "SW52b2tlLU1pbWlrYXR6"
        $m_invoke   = "SW52b2tlLU1pbWlrYXR6" ascii

        // General URL-safe marker: long run of [A-Za-z0-9_-] with no '+' or '/'
        $urlsafe_only = /[A-Za-z0-9_-]{200,}/

    condition:
        any of ($m_*)
        or ($urlsafe_only and any of ($m_*))
}
