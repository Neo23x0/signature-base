/*

   Generic Anomalies

   Florian Roth
   BSK Consulting GmbH

	License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
	Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/

*/
rule Embedded_EXE_Cloaking {
        meta:
                description = "Detects an embedded executable in a non-executable file"
                author = "Florian Roth"
                date = "2015/02/27"
                score = 65
        strings:
                $noex_png = { 89 50 4E 47 }
                $noex_pdf = { 25 50 44 46 }
                $noex_rtf = { 7B 5C 72 74 66 31 }
                $noex_jpg = { FF D8 FF E0 }
                $noex_gif = { 47 49 46 38 }
                $mz  = { 4D 5A }
                $a1 = "This program cannot be run in DOS mode"
                $a2 = "This program must be run under Win32"
        condition:
                (
                        ( $noex_png at 0 ) or
                        ( $noex_pdf at 0 ) or
                        ( $noex_rtf at 0 ) or
                        ( $noex_jpg at 0 ) or
                        ( $noex_gif at 0 )
                )
                and
                for any i in (1..#mz): ( @a1 < ( @mz[i] + 200 ) or @a2 < ( @mz[i] + 200 ) )
}

rule Cloaked_as_JPG {
   meta:
      description = "Detects a cloaked file as JPG"
      author = "Florian Roth (eval section from Didier Stevens)"
      date = "2015/02/29"
      score = 40
   strings:
      $fp1 = "<!DOCTYPE" ascii
   condition:
      uint16be(0x00) != 0xFFD8 and
      extension matches /\.jpg/i and
      not uint32be(0) == 0x4749463839 and /* GIF Header */
      /* and
      not filepath contains "ASP.NET" */
      not $fp1 in (0..30) and
      not uint32be(0) == 0x89504E47 /* PNG Header */
}

/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-12-21
    Identifier: Uncommon File Sizes
*/

rule Suspicious_Size_explorer_exe {
    meta:
        description = "Detects uncommon file size of explorer.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "explorer.exe"
        and not filepath contains "teamviewer"
        and ( filesize < 800KB or filesize > 5000KB )
}

rule Suspicious_Size_chrome_exe {
    meta:
        description = "Detects uncommon file size of chrome.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "chrome.exe"
        and ( filesize < 500KB or filesize > 2000KB )
}

rule Suspicious_Size_csrss_exe {
    meta:
        description = "Detects uncommon file size of csrss.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "csrss.exe"
        and ( filesize > 18KB )
}

rule Suspicious_Size_iexplore_exe {
    meta:
        description = "Detects uncommon file size of iexplore.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "iexplore.exe"
        and not filepath contains "teamviewer"
        and ( filesize < 75KB or filesize > 910KB )
}

rule Suspicious_Size_firefox_exe {
    meta:
        description = "Detects uncommon file size of firefox.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "firefox.exe"
        and ( filesize < 265KB or filesize > 910KB )
}

rule Suspicious_Size_java_exe {
    meta:
        description = "Detects uncommon file size of java.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "java.exe"
        and ( filesize < 42KB or filesize > 900KB )
}

rule Suspicious_Size_lsass_exe {
    meta:
        description = "Detects uncommon file size of lsass.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "lsass.exe"
        and ( filesize < 10KB or filesize > 58KB )
}

rule Suspicious_Size_svchost_exe {
    meta:
        description = "Detects uncommon file size of svchost.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "svchost.exe"
        and ( filesize < 14KB or filesize > 60KB )
}

rule Suspicious_Size_winlogon_exe {
    meta:
        description = "Detects uncommon file size of winlogon.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "winlogon.exe"
        and ( filesize < 279KB or filesize > 750KB )
}

rule Suspicious_Size_igfxhk_exe {
    meta:
        description = "Detects uncommon file size of igfxhk.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
    condition:
        uint16(0) == 0x5a4d
        and filename == "igfxhk.exe"
        and ( filesize < 200KB or filesize > 265KB )
}

rule Suspicious_Size_servicehost_dll {
    meta:
        description = "Detects uncommon file size of servicehost.dll"
        author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "servicehost.dll"
        and filesize > 150KB
}

rule Suspicious_Size_rundll32_exe {
    meta:
        description = "Detects uncommon file size of rundll32.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "rundll32.exe"
        and ( filesize < 30KB or filesize > 80KB )
}

rule Suspicious_Size_taskhost_exe {
    meta:
        description = "Detects uncommon file size of taskhost.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "taskhost.exe"
        and ( filesize < 45KB or filesize > 120KB )
}

rule Suspicious_Size_spoolsv_exe {
    meta:
        description = "Detects uncommon file size of spoolsv.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "spoolsv.exe"
        and ( filesize < 50KB or filesize > 930KB )
}

rule Suspicious_Size_smss_exe {
    meta:
        description = "Detects uncommon file size of smss.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "smss.exe"
        and ( filesize < 40KB or filesize > 320KB )
}

rule Suspicious_Size_wininit_exe {
    meta:
        description = "Detects uncommon file size of wininit.exe"
        author = "Florian Roth"
        score = 60
        date = "2015-12-23"
    condition:
        uint16(0) == 0x5a4d
        and filename == "wininit.exe"
        and ( filesize < 90KB or filesize > 400KB )
}

rule Suspicious_AutoIt_by_Microsoft {
   meta:
      description = "Detects a AutoIt script with Microsoft identification"
      author = "Florian Roth"
      reference = "Internal Research - VT"
      date = "2017-12-14"
      score = 60
      hash1 = "c0cbcc598d4e8b501aa0bd92115b4c68ccda0993ca0c6ce19edd2e04416b6213"
   strings:
      $s1 = "Microsoft Corporation. All rights reserved" fullword wide
      $s2 = "AutoIt" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}
