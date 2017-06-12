/*
    Yara Rule Set
    Author: Dragos Inc
    Date: 2016-06-12
    Identifier: Crash Override
*/

import "pe"

rule dragos_crashoverride_suspcious
{
    meta: 
        description = "CRASHOVERRIDE v1 Wiper" 
        author = "Dragos Inc"
        reference = "https://t.co/h8QaIP4FU8"
    strings:
        $s0 = "SYS_BASCON.COM" fullword nocase wide 
        $s1 = ".pcmp" fullword nocase wide
        $s2 = ".pcmi" fullword nocase wide
        $s3 = ".pcmt" fullword nocase wide
        $s4 = ".cin" fullword nocase wide
    condition:
        pe.exports("Crash") and any of ($s*)
}

rule dragos_crashoverride_exporting_dlls {
    meta: 
        description = "CRASHOVERRIDE v1 Suspicious Export"
        author = "Dragos Inc"
        reference = "https://t.co/h8QaIP4FU8"
    condition:
        pe.exports("Crash") & pe.characteristics
}

rule dragos_crashoverride_name_search {
    meta:
        description = "CRASHOVERRIDE v1 Suspicious Strings and Export"
        author = "Dragos Inc"
        reference = "https://t.co/h8QaIP4FU8"
    strings:
        $s0 = "101.dll" fullword nocase wide
        $s1 = "Crash101.dll" fullword nocase wide
        $s2 = "104.dll" fullword nocase wide
        $s3 = "Crash104.dll" fullword nocase wide
        $s4 = "61850.dll" fullword nocase wide
        $s5 = "Crash61850.dll" fullword nocase wide
        $s6 = "OPCClientDemo.dll" fullword nocase wide
        $s7 = "OPC" fullword nocase wide
        $s8 = "CrashOPCClientDemo.dll" fullword nocase wide
        $s9 = "D2MultiCommService.exe" fullword nocase wide
        $s10 = "CrashD2MultiCommService.exe" fullword nocase wide $s11 = "61850.exe" fullword nocase wide
        $s12 = "OPC.exe" fullword nocase wide
        $s13 = "haslo.exe" fullword nocase wide
        $s14 = "haslo.dat" fullword nocase wide
    condition:
        any of ($s*) and pe.exports("Crash")
}

  
   