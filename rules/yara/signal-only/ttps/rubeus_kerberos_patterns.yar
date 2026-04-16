// Rubeus + Kerberos-abuse fingerprints. Covers the binary itself (stable
// format strings, subcommand parser), the /ticket:<base64> payload that
// Rubeus hands to pass-the-ticket operations, managed-assembly clusters
// that hit the LSA Kerberos package directly, and kerberoast-style
// encryption-type indicators.
//
// Tier: signal-only. These strings legitimately appear in Impacket tools,
// MIT krb5 source, security training materials, and Rubeus itself on a
// red-team lab machine. Detections should chain with process-creation
// context (lsass handle opens, /ticket: cmdline, child of unusual parent)
// before triggering response actions.

// ---------------------------------------------------------------------------
// Rubeus binary fingerprint — stable format strings + subcommand names.
// Survives identifier-renaming obfuscators because the Console.WriteLine
// strings must remain readable (they're the tool's UX).
// ---------------------------------------------------------------------------
rule Rubeus_Binary_Fingerprint
{
    meta:
        description = "Compiled Rubeus binary or derivative — matches stable format strings and subcommand parser tokens"
        author      = "NortonEDR"
        reference   = "https://github.com/GhostPack/Rubeus"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Output format strings baked into Rubeus's Console output
        $fmt_action       = "[*] Action:"                           ascii
        $fmt_dc           = "[*] Using domain controller:"          ascii
        $fmt_asreq        = "[*] Building AS-REQ"                   ascii
        $fmt_asrep        = "[+] TGT request successful!"           ascii
        $fmt_tgs          = "[*] Building TGS-REQ"                  ascii
        $fmt_cache_saved  = "ticket cache saved to"                 ascii nocase
        $fmt_base64       = "base64(ticket.kirbi)"                  ascii
        $fmt_renew        = "Starting ticket renewal"               ascii nocase
        $fmt_no_preauth   = "[+] AS-REP roasting!"                  ascii
        $fmt_kerberoast   = "[*] Kerberoasting "                    ascii
        $fmt_pt_t         = "[+] Ticket successfully imported"      ascii

        // Subcommand names (first argument parser table in Rubeus.Program)
        $cmd_asktgt       = "asktgt"                                ascii fullword
        $cmd_asktgs       = "asktgs"                                ascii fullword
        $cmd_kerberoast   = "kerberoast"                            ascii fullword
        $cmd_asrep        = "asreproast"                            ascii fullword
        $cmd_s4u          = "s4u"                                   ascii fullword
        $cmd_tgtdeleg     = "tgtdeleg"                              ascii fullword
        $cmd_ptt          = "ptt"                                   ascii fullword
        $cmd_golden       = "golden"                                ascii fullword
        $cmd_silver       = "silver"                                ascii fullword
        $cmd_describe     = "describe"                              ascii fullword
        $cmd_triage       = "triage"                                ascii fullword
        $cmd_createnetonly = "createnetonly"                        ascii fullword

        // Author / project signatures
        $sig_harmj0y      = "HarmJ0y"                               ascii nocase
        $sig_rubeus       = "Rubeus"                                ascii
        $sig_rubeus_ns    = "Rubeus.Commands"                       ascii

    condition:
        2 of ($fmt_*)
        or (3 of ($cmd_*) and 1 of ($sig_*, $fmt_*))
        or ($sig_rubeus_ns and any of ($cmd_*))
}


// ---------------------------------------------------------------------------
// Kirbi / KRB-CRED blob in memory. A .kirbi ticket file (Microsoft's KRB-CRED
// wrapper) always contains the KRB5 OID "1.2.840.113554.1.2.2" encoded in
// DER. That 11-byte sequence (06 09 2A 86 48 86 F7 12 01 02 02) renders, in
// base64, as "BgkqhkiG9xICAgI" — a 15-char ASCII string present in every
// /ticket:<base64> argument, every dumped kirbi, and every PTT session.
// ---------------------------------------------------------------------------
rule Kerberos_KirbiBlob_Memory
{
    meta:
        description = "Kerberos KRB-CRED / kirbi ticket blob present in memory or on disk — base64-encoded KRB5 OID marker and/or raw DER application-class tag"
        author      = "NortonEDR"
        reference   = "https://datatracker.ietf.org/doc/html/rfc4120#section-5.8"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Base64 of DER-encoded KRB5 OID — appears in every Rubeus /ticket:
        // command-line argument and every base64-wrapped .kirbi file
        $b64_oid_krb5  = "BgkqhkiG9xICAgI"                          ascii

        // Raw DER: [APPLICATION 22] = KRB-CRED (kirbi)
        //         76 82 ??         — outer application tag + 2-byte length
        //         followed within ~16 bytes by SEQUENCE + KRB5 OID bytes
        $der_krbcred   = { 76 82 ?? ?? 30 82 ?? ?? [0-16] 06 09 2A 86 48 86 F7 12 01 02 02 }

        // Raw DER: [APPLICATION 10] = AS-REQ
        $der_asreq     = { 6A 82 ?? ?? 30 82 ?? ?? [0-64] 06 09 2A 86 48 86 F7 12 01 02 02 }

        // Raw DER: [APPLICATION 13] = AS-REP
        $der_asrep     = { 6D 82 ?? ?? 30 82 ?? ?? [0-64] 06 09 2A 86 48 86 F7 12 01 02 02 }

        // Raw DER: [APPLICATION 12] = TGS-REQ
        $der_tgsreq    = { 6C 82 ?? ?? 30 82 ?? ?? [0-64] 06 09 2A 86 48 86 F7 12 01 02 02 }

        // Literal KRB5 OID bytes
        $oid_krb5_raw  = { 06 09 2A 86 48 86 F7 12 01 02 02 }

        // File path markers commonly used when dumping ticket caches
        $path_krb5cc   = "krb5cc_"                                  ascii
        $path_kirbi    = ".kirbi"                                   ascii nocase

    condition:
        $b64_oid_krb5
        or any of ($der_*)
        or ($oid_krb5_raw and any of ($path_*))
}


// ---------------------------------------------------------------------------
// Managed-assembly cluster that talks to the LSA Kerberos package directly.
// The combination of LsaCallAuthenticationPackage + KerbSubmitTicketMessage
// constants + Kerberos structure field names is the Rubeus PTT code path.
// ---------------------------------------------------------------------------
rule ManagedInterop_KerberosLsa_Cluster
{
    meta:
        description = "Managed assembly contains the LSA + Kerberos submit-ticket cluster typical of Rubeus / SharpKatz / Impacket-to-C# ports"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $clr_marker = "BSJB"

        // LSA APIs Rubeus uses
        $lsa_call         = "LsaCallAuthenticationPackage"          ascii
        $lsa_connect      = "LsaConnectUntrusted"                   ascii
        $lsa_register     = "LsaRegisterLogonProcess"               ascii
        $lsa_lookup       = "LsaLookupAuthenticationPackage"        ascii
        $lsa_enum         = "LsaEnumerateLogonSessions"             ascii
        $lsa_getsession   = "LsaGetLogonSessionData"                ascii

        // Kerberos submit-package message type names
        $kmsg_submit      = "KerbSubmitTicketMessage"               ascii
        $kmsg_purge       = "KerbPurgeTicketMessage"                ascii
        $kmsg_retrieve    = "KerbRetrieveTicketMessage"             ascii
        $kmsg_query       = "KerbQueryTicketCacheMessage"           ascii
        $kmsg_queryex     = "KerbQueryTicketCacheExMessage"         ascii
        $kmsg_change      = "KerbChangePasswordMessage"             ascii

        // Kerberos structure names that Rubeus pipes through interop
        $ks_submit_req    = "KERB_SUBMIT_TKT_REQUEST"               ascii
        $ks_purge_req     = "KERB_PURGE_TKT_CACHE_REQUEST"          ascii
        $ks_query_req     = "KERB_QUERY_TKT_CACHE_REQUEST"          ascii
        $ks_external_name = "KERB_EXTERNAL_NAME"                    ascii
        $ks_external_tkt  = "KERB_EXTERNAL_TICKET"                  ascii
        $ks_crypto_key    = "KERB_CRYPTO_KEY"                       ascii

        // Rubeus-specific managed class names (appear across forks)
        $cl_lsa           = "LSA.cs"                                ascii
        $cl_ticketter     = "Ticketer"                              ascii
        $cl_commands      = "Rubeus.Commands"                       ascii

    condition:
        $clr_marker and
        (
            (any of ($lsa_*) and any of ($kmsg_*))
            or (any of ($lsa_*) and any of ($ks_*))
            or (any of ($kmsg_*) and any of ($ks_*))
            or any of ($cl_*)
        )
}


// ---------------------------------------------------------------------------
// Kerberoasting / AS-REP roasting indicators. Hash cracking of service
// tickets requires requesting TGS-REP with RC4-HMAC (etype 23) or AES
// encryption type preferences. A managed assembly that references these
// etype constants alongside Kerberos APIs is requesting tickets with
// crackable etypes — the kerberoast primitive.
// ---------------------------------------------------------------------------
rule Kerberoast_EncType_Indicators
{
    meta:
        description = "Managed assembly references Kerberos encryption-type constants / structure names used by kerberoasting and AS-REP roasting tools"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $clr_marker = "BSJB"

        // Etype constant names that Rubeus/Impacket expose
        $et_rc4_name      = "rc4_hmac"                              ascii nocase
        $et_rc4_dash      = "rc4-hmac"                              ascii nocase
        $et_aes128        = "aes128_cts_hmac_sha1"                  ascii nocase
        $et_aes128_dash   = "aes128-cts-hmac-sha1"                  ascii nocase
        $et_aes256        = "aes256_cts_hmac_sha1"                  ascii nocase
        $et_aes256_dash   = "aes256-cts-hmac-sha1"                  ascii nocase
        $et_des_cbc       = "des-cbc-md5"                           ascii nocase

        // Enum/field names
        $enum_etype       = "KERB_ETYPE"                            ascii
        $enum_rc4         = "rc4_hmac_old_exp"                      ascii nocase
        $enum_encpart     = "EncTicketPart"                         ascii
        $enum_tgsrep      = "KRB-TGS-REP"                           ascii
        $enum_authdata    = "AuthorizationData"                     ascii
        $enum_pac         = "AuthenticationInformation"             ascii

        // SPN-scanning / kerberoast helper strings
        $sk_spn           = "servicePrincipalName"                  ascii
        $sk_hashcat_krb  = "krb5tgs$"                               ascii
        $sk_hashcat_asr  = "krb5asrep$"                             ascii
        $sk_john_krb     = "$krb5tgs$"                              ascii
        $sk_john_asr     = "$krb5asrep$"                            ascii

        // Kerberos API names (partial overlap with other rules, kept here
        // so this rule fires standalone on non-managed binaries too)
        $api_asktgs       = "AskTGS"                                ascii
        $api_asktgt       = "AskTGT"                                ascii
        $api_roast        = "Roast"                                 ascii

    condition:
        // Hashcat/John format markers are unambiguous
        any of ($sk_hashcat_*, $sk_john_*)
        or (
            // Or 2+ etype references + any Kerberos structure reference
            (2 of ($et_*) and any of ($enum_*, $api_*))
        )
        or (
            // Or managed assembly with SPN scan + etype + API
            $clr_marker and $sk_spn and any of ($et_*) and any of ($api_*, $enum_*)
        )
}
