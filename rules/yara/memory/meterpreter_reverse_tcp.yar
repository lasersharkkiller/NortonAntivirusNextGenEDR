rule Meterpreter_ReverseTcp_Stager_Memory
{
    meta:
        description = "Metasploit windows/x64/meterpreter/reverse_tcp stager opcode pattern."
        author      = "NortonEDR"
        reference   = "https://github.com/rapid7/metasploit-framework"
        tier        = "memory"
        severity    = "critical"
        scan_target = "process_memory"

    strings:
        // Stager prologue: FC 48 83 E4 F0 ...  -> cld; and rsp, -0x10 (classic MSF x64 shellcode head)
        $prologue = { FC 48 83 E4 F0 E8 C? 00 00 00 }

        // Stager imports WinSock via hashed PEB walk; these are common constants
        $ws2_32_hash = { 72 FE B3 16 }    // ws2_32!WSAStartup hash
        $wsa_hash    = { 57 89 9F C6 }    // ws2_32!WSASocket hash
        $connect     = { 61 4C 6C 29 }    // ws2_32!connect hash

        // LPORT/LHOST structure — the stager embeds a sockaddr_in struct
        // 02 00  => AF_INET, followed by port (BE) and IPv4
        $sockaddr_fragment = { 68 02 00 ?? ?? 89 E6 }

    condition:
        $prologue and any of ($ws2_32_hash, $wsa_hash, $connect, $sockaddr_fragment)
}


rule Generic_x64_Shellcode_StagerPrologue_Memory
{
    meta:
        description = "Broad x64 shellcode prologue commonly used by Metasploit, Sliver, and handwritten stagers — high recall, medium FP. Intentionally in memory/ tier (not quarantine-safe)."
        author      = "NortonEDR"
        tier        = "memory"
        severity    = "medium"
        scan_target = "process_memory"

    strings:
        // PEB-walk: mov rax, gs:[0x60]
        $peb_access = { 65 48 8B ?? 60 00 00 00 }

        // Classic stager entrypoint: fnstenv, pop + XOR decode loop
        $fnstenv = { D9 74 24 F4 5? 81 C? ?? ?? ?? ?? }

    condition:
        any of them
}
