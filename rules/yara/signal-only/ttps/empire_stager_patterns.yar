// PowerShell Empire / Starkiller stager, agent, and C2-route fingerprints.
// Empire's launcher is a short bat/vbs/hta/js bootstrap that decodes a Base64
// blob, XORs it against a static 4-byte key, and IEX's the result. The inner
// agent body, once deobfuscated in memory, is full of stable script-level
// variable names and module dispatch tokens. Empire 5 (BC Security fork)
// renamed several routes and added Starkiller-specific endpoints.
//
// Tier: signal-only — these strings legitimately appear in Empire itself,
// BC-Security's public repo, PowerSploit training material, and red-team
// course ISOs. Chain with process context (parent = cmd.exe/wscript.exe/
// winword.exe, -NoProfile + -WindowStyle Hidden, outbound HTTP to /news.php
// on a non-Microsoft host) before quarantine action.

// ---------------------------------------------------------------------------
// Empire PS stager decode chain. Stable shape across v2/3/4 and Starkiller:
//   $data = [System.Convert]::FromBase64String($encoded)
//   for($i=0; $i -lt $data.Length; $i++) {
//       $data[$i] = $data[$i] -bxor $key[$i % $key.Length]
//   }
//   IEX ([System.Text.Encoding]::ASCII.GetString($data))
// ---------------------------------------------------------------------------
rule Empire_Stager_Base64Xor_IEX_Chain
{
    meta:
        description = "PowerShell Empire / Starkiller stager: Base64 → single-key XOR → IEX decode chain"
        author      = "NortonEDR"
        reference   = "https://github.com/BC-SECURITY/Empire"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // The XOR loop — Empire's fixed wording
        $xor_loop_a = "-bxor $key[$i % $key.Length]"                                ascii nocase
        $xor_loop_b = "-bxor $k[$i % $k.Length]"                                    ascii nocase
        $xor_loop_c = "-bxor $key[($i % $key.Length)]"                              ascii nocase
        $xor_loop_d = "-bxor($k[$i%$k.length])"                                     ascii nocase

        // Base64 decode entry
        $b64_a = "[System.Convert]::FromBase64String"                               ascii nocase
        $b64_b = "[Convert]::FromBase64String"                                      ascii nocase

        // IEX of ASCII/UTF8 GetString — end of decode chain
        $iex_a = "IEX ([System.Text.Encoding]::ASCII.GetString"                     ascii nocase
        $iex_b = "iex([System.Text.Encoding]::ASCII.GetString"                      ascii nocase
        $iex_c = "Invoke-Expression ([System.Text.Encoding]::ASCII.GetString"       ascii nocase
        $iex_d = "[System.Text.Encoding]::UTF8.GetString"                           ascii nocase

        // PowerShell wide-form (when written to a launcher .ps1)
        $xor_loop_w = "-bxor $key[$i % $key.Length]"                                wide  nocase
        $b64_w      = "[System.Convert]::FromBase64String"                          wide  nocase

    condition:
        (any of ($xor_loop_*) and any of ($b64_a, $b64_b, $b64_w))
        or (any of ($xor_loop_*) and any of ($iex_*))
        or ($xor_loop_w and $b64_w)
}


// ---------------------------------------------------------------------------
// Empire agent internals. After deobfuscation, the agent script defines a
// script-scope state block with stable names. These strings appear in memory
// of any process running the Empire agent, plus in PowerShell script-block
// logging events (EventID 4104).
// ---------------------------------------------------------------------------
rule Empire_Agent_ScriptInternals
{
    meta:
        description = "PowerShell Empire agent script-scope state: tasking queue, delegate resolver, AES helpers"
        author      = "NortonEDR"
        reference   = "https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/agent/agent.ps1"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Script-scope state (Empire-only naming)
        $s_taskresults  = "$script:TaskResults"                                     ascii nocase
        $s_getdelegate  = "$script:GetDelegate"                                     ascii nocase
        $s_cliprecord   = "$script:ClipRecord"                                      ascii nocase
        $s_keystrokes   = "$script:KeyStrokes"                                      ascii nocase
        $s_ps_version   = "$script:PSVersion"                                       ascii nocase
        $s_checkin_i    = "$script:CheckinIntervals"                                ascii nocase
        $s_jitter       = "$script:AgentJitter"                                     ascii nocase
        $s_working_hrs  = "$script:WorkingHours"                                    ascii nocase
        $s_lost_limit   = "$script:LostLimit"                                       ascii nocase
        $s_kill_date    = "$script:KillDate"                                        ascii nocase

        // AES helpers — Empire's own function names (not shared w/ Mimikatz/Rubeus)
        $f_encrypt      = "function Encrypt-Bytes"                                  ascii nocase
        $f_decrypt      = "function Decrypt-Bytes"                                  ascii nocase
        $f_create_aes   = "function Create-AesCipher"                               ascii nocase
        $f_new_agent    = "function New-AgentPacket"                                ascii nocase
        $f_decode_pkt   = "function Decode-Packet"                                  ascii nocase
        $f_process_pkt  = "function Process-Packet"                                 ascii nocase
        $f_encode_pkt   = "function Encode-Packet"                                  ascii nocase

        // Tasking type codes Empire reserves (TASK_* constants in agent.ps1)
        $t_1       = "TASK_EXIT"                                                    ascii
        $t_2       = "TASK_SET_DELAY"                                               ascii
        $t_3       = "TASK_SET_SERVERS"                                             ascii
        $t_4       = "TASK_GET_JOBS"                                                ascii
        $t_5       = "TASK_CSHARP"                                                  ascii
        $t_6       = "TASK_IPCONFIG"                                                ascii

    condition:
        3 of ($s_*)
        or 2 of ($f_*)
        or (any of ($s_*) and any of ($f_*))
        or 2 of ($t_*)
}


// ---------------------------------------------------------------------------
// Empire module-name cluster. Agent tasking blobs and module outputs carry
// the Empire module path as the "type" field — these strings appear in both
// the agent buffer and in tasking HTTP bodies.
// ---------------------------------------------------------------------------
rule Empire_Module_Dispatch_Cluster
{
    meta:
        description = "Empire module dispatch path strings (situational_awareness/, credentials/, lateral_movement/, management/)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $m1  = "situational_awareness/host/"                                        ascii nocase
        $m2  = "situational_awareness/network/"                                     ascii nocase
        $m3  = "credentials/mimikatz/"                                              ascii nocase
        $m4  = "credentials/powerdump"                                              ascii nocase
        $m5  = "credentials/vaultcredential"                                        ascii nocase
        $m6  = "lateral_movement/invoke_psexec"                                     ascii nocase
        $m7  = "lateral_movement/invoke_wmi"                                        ascii nocase
        $m8  = "lateral_movement/invoke_psremoting"                                 ascii nocase
        $m9  = "lateral_movement/invoke_smbexec"                                    ascii nocase
        $m10 = "management/spawn"                                                   ascii nocase
        $m11 = "management/psinject"                                                ascii nocase
        $m12 = "management/runas"                                                   ascii nocase
        $m13 = "privesc/bypassuac_"                                                 ascii nocase
        $m14 = "privesc/powerup/"                                                   ascii nocase
        $m15 = "persistence/userland/"                                              ascii nocase
        $m16 = "persistence/elevated/"                                              ascii nocase
        $m17 = "collection/keylogger"                                               ascii nocase
        $m18 = "collection/screenshot"                                              ascii nocase
        $m19 = "collection/clipboard_monitor"                                       ascii nocase
        $m20 = "exfiltration/exfil_dropbox"                                         ascii nocase

    condition:
        2 of them
}


// ---------------------------------------------------------------------------
// Empire / Starkiller default HTTP listener URIs + user-agent. These match
// the out-of-the-box install. Defenders see them in proxy logs, and the
// strings appear literally in the agent's $TaskingURIs array.
// ---------------------------------------------------------------------------
rule Empire_C2_Default_Routes
{
    meta:
        description = "PowerShell Empire / Starkiller default HTTP listener URIs and user-agent strings"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Classic Empire 2/3/4 default tasking routes
        $u1  = "/login/process.php"                                                 ascii
        $u2  = "/admin/get.php"                                                     ascii
        $u3  = "/admin/post.php"                                                    ascii
        $u4  = "/admin/controlpanel.php"                                            ascii
        $u5  = "/news.php"                                                          ascii
        $u6  = "/news.asp"                                                          ascii
        $u7  = "/news/index.php"                                                    ascii
        $u8  = "/login.php?page="                                                   ascii

        // Starkiller (Empire 5) routes
        $s1  = "/emp_agent"                                                         ascii nocase
        $s2  = "/api/v2/agents/"                                                    ascii nocase
        $s3  = "/api/v2/admin/"                                                     ascii nocase

        // Default $TaskingURIs array literal
        $arr = "$TaskingURIs"                                                       ascii nocase

        // Default user-agent baked into stager — IE11 on Windows 7 WoW64
        $ua  = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"          ascii nocase

        // Session-cookie name (Empire's default)
        $cookie = "session="                                                        ascii

    condition:
        2 of ($u*, $s*)
        or ($arr and any of ($u*, $s*))
        or ($ua and any of ($u*, $s*))
}
