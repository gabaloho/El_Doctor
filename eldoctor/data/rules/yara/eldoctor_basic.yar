/*
  El Doctor bundled YARA rules (small, high-confidence set).
  Add community rules (e.g. YARA-Forge, Neo23x0/signature-base) via detection.yara.rules_dirs.
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test string"
        severity = "critical"
        mitre = "T1204.002"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar at 0 or $eicar
}

rule XMRig_Miner_Strings
{
    meta:
        description = "XMRig / RandomX cryptominer strings"
        severity = "critical"
        mitre = "T1496"
    strings:
        $s1 = "xmrig" ascii nocase
        $s2 = "stratum+tcp://" ascii
        $s3 = "randomx" ascii nocase
        $s4 = "--donate-level" ascii
        $s5 = "cryptonight" ascii nocase
    condition:
        3 of them
}

rule Linux_Reverse_Shell_Script
{
    meta:
        description = "Script containing a reverse shell one-liner"
        severity = "high"
        mitre = "T1059.004"
    strings:
        $a = "/dev/tcp/" ascii
        $b = "bash -i" ascii
        $c = "pty.spawn" ascii
        $d = "socket.socket" ascii
        $e = "os.dup2" ascii
    condition:
        filesize < 200KB and (($a and $b) or ($c and $d and $e))
}
