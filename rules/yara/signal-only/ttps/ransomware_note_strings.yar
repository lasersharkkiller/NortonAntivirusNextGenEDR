// Ransom-note fingerprint. The note itself — whether dropped as README.txt,
// HOW_TO_DECRYPT.hta, or embedded in the encryptor binary — survives heavy
// obfuscation of the executable (the note text has to be human-readable).
// High-signal cluster: encryption claim + payment channel + TOR/Bitcoin
// reference. Threshold 2-of-N keeps generic security/privacy docs from firing.
//
// Tier: signal-only — ransom notes also appear in malware research papers,
// phishing-awareness training materials, and EDR/MDR documentation.

rule Ransomware_NoteStrings_Generic
{
    meta:
        description = "File or memory region contains the string cluster typical of a ransomware extortion note"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        // Encryption claim
        $e1  = "your files have been encrypted"      ascii nocase
        $e2  = "your files have been encrypted"      wide  nocase
        $e3  = "all your files are encrypted"        ascii nocase
        $e4  = "all your files are encrypted"        wide  nocase
        $e5  = "your network has been encrypted"     ascii nocase
        $e6  = "all your data has been"              ascii nocase
        $e7  = "files are locked"                    ascii nocase
        $e8  = "restore your files"                  ascii nocase
        $e9  = "decryption tool"                     ascii nocase
        $e10 = "decryption key"                      ascii nocase
        $e11 = "private key"                         ascii nocase
        $e12 = "unique id"                           ascii nocase
        $e13 = "personal id"                         ascii nocase

        // Payment channel
        $p1  = "bitcoin"                             ascii nocase
        $p2  = "bitcoin"                             wide  nocase
        $p3  = "btc wallet"                          ascii nocase
        $p4  = "send payment"                        ascii nocase
        $p5  = "monero"                              ascii nocase
        $p6  = "xmr wallet"                          ascii nocase
        $p7  = "ethereum"                            ascii nocase

        // Anonymity / contact
        $t1  = ".onion"                              ascii nocase
        $t2  = ".onion"                              wide  nocase
        $t3  = "tor browser"                         ascii nocase
        $t4  = "tor-browser"                         ascii nocase
        $t5  = "qtox"                                ascii nocase
        $t6  = "session id:"                         ascii nocase
        $t7  = "protonmail"                          ascii nocase
        $t8  = "tutanota"                            ascii nocase

        // Extortion pressure
        $x1  = "do not rename"                       ascii nocase
        $x2  = "do not modify"                       ascii nocase
        $x3  = "will be doubled"                     ascii nocase
        $x4  = "you have 72 hours"                   ascii nocase
        $x5  = "will be published"                   ascii nocase
        $x6  = "your data will be"                   ascii nocase
        $x7  = "contact us at"                       ascii nocase

        // Well-known ransomware IDs / project names
        $n1  = "LockBit"                             ascii
        $n2  = "Conti"                               ascii fullword
        $n3  = "BlackCat"                            ascii
        $n4  = "ALPHV"                               ascii
        $n5  = "Ryuk"                                ascii fullword
        $n6  = "REvil"                               ascii
        $n7  = "Sodinokibi"                          ascii
        $n8  = "BlackBasta"                          ascii
        $n9  = "Akira"                               ascii fullword
        $n10 = "Clop"                                ascii fullword

    condition:
        // Require >=2 of the generic categories, OR any named-family hit
        // (family names are high-precision — a single match is enough).
        (
            (any of ($e*) ? 1 : 0) +
            (any of ($p*) ? 1 : 0) +
            (any of ($t*) ? 1 : 0) +
            (any of ($x*) ? 1 : 0)
        ) >= 2
        or any of ($n*)
}
