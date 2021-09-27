/*

   Generic Anomalies

   Florian Roth
   Nextron Systems GmbH

	License: Detetction Rule License 1.1 (https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md)

*/
rule Embedded_EXE_Cloaking {
        meta:
                description = "Detects an embedded executable in a non-executable file"
                license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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
      description = "Detects a non-JPEG file cloaked as JPG"
      author = "Florian Roth"
      date = "2015/03/02"
      modified = "2021/06/08"
      score = 50
   strings:
      $fp1 = "<!DOCTYPE" ascii
   condition:
      uint16be(0) != 0xFFD8 and extension == ".jpg"
      and filetype != "GIF" and
      not $fp1 in (0..30) and
      not uint16(0) == 0x8b1f and /* GZIP */
      not uint16(0) == 0x4d42 and /* BMP */
      not uint32(0) == 0x474E5089 and /* PNG Header */
      not filename matches /\$I[A-Z0-9]{6}/
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
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "explorer.exe"
        and not filepath contains "teamviewer"
        and ( filesize < 800KB or filesize > 5000KB )
}

rule Suspicious_Size_chrome_exe {
    meta:
        description = "Detects uncommon file size of chrome.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "chrome.exe"
        and ( filesize < 500KB or filesize > 3000KB )
}

rule Suspicious_Size_csrss_exe {
    meta:
        description = "Detects uncommon file size of csrss.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "csrss.exe"
        and ( filesize > 18KB )
}

rule Suspicious_Size_iexplore_exe {
    meta:
        description = "Detects uncommon file size of iexplore.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "iexplore.exe"
        and not filepath contains "teamviewer"
        and ( filesize < 75KB or filesize > 910KB )
}

rule Suspicious_Size_firefox_exe {
    meta:
        description = "Detects uncommon file size of firefox.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "firefox.exe"
        and (
        	(
        		filepath not contains "Tor Browser"
        		and ( filesize < 265KB or filesize > 910KB )
        	) or (
        		filepath contains "Tor Browser"
        		and ( filesize < 265KB or filesize > 1800KB )
        	)
        )	
}

rule Suspicious_Size_java_exe {
    meta:
        description = "Detects uncommon file size of java.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "java.exe"
        and ( filesize < 30KB or filesize > 900KB )
}

rule Suspicious_Size_lsass_exe {
    meta:
        description = "Detects uncommon file size of lsass.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "lsass.exe"
        and ( filesize < 10KB or filesize > 100KB )
}

rule Suspicious_Size_svchost_exe {
    meta:
        description = "Detects uncommon file size of svchost.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "svchost.exe"
        and ( filesize < 14KB or filesize > 100KB )
}

rule Suspicious_Size_winlogon_exe {
    meta:
        description = "Detects uncommon file size of winlogon.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "winlogon.exe"
        and ( filesize < 279KB or filesize > 970KB )
}

rule Suspicious_Size_igfxhk_exe {
    meta:
        description = "Detects uncommon file size of igfxhk.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-21"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "igfxhk.exe"
        and ( filesize < 200KB or filesize > 265KB )
}

rule Suspicious_Size_servicehost_dll {
    meta:
        description = "Detects uncommon file size of servicehost.dll"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "servicehost.dll"
        and filesize > 150KB
}

rule Suspicious_Size_rundll32_exe {
    meta:
        description = "Detects uncommon file size of rundll32.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "rundll32.exe"
        and ( filesize < 30KB or filesize > 80KB )
}

rule Suspicious_Size_taskhost_exe {
    meta:
        description = "Detects uncommon file size of taskhost.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "taskhost.exe"
        and ( filesize < 45KB or filesize > 120KB )
}

rule Suspicious_Size_spoolsv_exe {
    meta:
        description = "Detects uncommon file size of spoolsv.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "spoolsv.exe"
        and ( filesize < 50KB or filesize > 930KB )
}

rule Suspicious_Size_smss_exe {
    meta:
        description = "Detects uncommon file size of smss.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "smss.exe"
        and ( filesize < 40KB or filesize > 320KB )
}

rule Suspicious_Size_wininit_exe {
    meta:
        description = "Detects uncommon file size of wininit.exe"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
        score = 60
        date = "2015-12-23"
        noarchivescan = 1
    condition:
        uint16(0) == 0x5a4d
        and filename == "wininit.exe"
        and ( filesize < 90KB or filesize > 450KB )
}

rule Suspicious_AutoIt_by_Microsoft {
   meta:
      description = "Detects a AutoIt script with Microsoft identification"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
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

rule SUSP_Size_of_ASUS_TuningTool {
   meta:
      description = "Detects an ASUS tuning tool with a suspicious size"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17"
      score = 60
      noarchivescan = 1
      hash1 = "d4e97a18be820a1a3af639c9bca21c5f85a3f49a37275b37fd012faeffcb7c4a"
   strings:
      $s1 = "\\Release\\ASGT.pdb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and filesize > 70KB and all of them
}

rule SUSP_PiratedOffice_2007 {
   meta:
      description = "Detects an Office document that was created with a pirated version of MS Office 2007"
      author = "Florian Roth"
      reference = "https://twitter.com/pwnallthethings/status/743230570440826886?lang=en"
      date = "2018-12-04"
      score = 40
      hash1 = "210448e58a50da22c0031f016ed1554856ed8abe79ea07193dc8f5599343f633"
   strings:
      $s7 = "<Company>Grizli777</Company>" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 300KB and all of them
}

rule SUSP_Scheduled_Task_BigSize {
   meta:
      description = "Detects suspiciously big scheduled task XML file as seen in combination with embedded base64 encoded PowerShell code"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-12-06"
   strings:
      $a0 = "<Task version=" ascii wide
      $a1 = "xmlns=\"http://schemas.microsoft.com/windows/" ascii wide

      $fp1 = "</Counter><Counter>" wide
      $fp2 = "Office Feature Updates Logon" wide
      $fp3 = "Microsoft Shared" fullword wide
   condition:
      uint16(0) == 0xfeff and filesize > 20KB and all of ($a*) and not 1 of ($fp*)
}

rule SUSP_Putty_Unnormal_Size {
   meta:
      description = "Detects a putty version with a size different than the one provided by Simon Tatham (could be caused by an additional signature or malware)"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-01-07"
      score = 50
      hash1 = "e5e89bdff733d6db1cffe8b3527e823c32a78076f8eadc2f9fd486b74a0e9d88"
      hash2 = "ce4c1b718b54973291aefdd63d1cca4e4d8d4f5353a2be7f139a290206d0c170"
      hash3 = "adb72ea4eab7b2efc2da6e72256b5a3bb388e9cdd4da4d3ff42a9fec080aa96f"
      hash4 = "1c0bd6660fa43fa90bd88b56cdd4a4c2ffb4ef9d04e8893109407aa7039277db"
   strings:
      $s1 = "SSH, Telnet and Rlogin client" fullword wide

      $v1 = "Release 0.6" wide
      $v2 = "Release 0.70" wide

      $fp1 = "KiTTY fork" fullword wide
   condition:
      uint16(0) == 0x5a4d
      and $s1 and 1 of ($v*)
      and not 1 of ($fp*)
      // has offset
      and filesize != 524288
      and filesize != 495616
      and filesize != 483328
      and filesize != 524288
      and filesize != 712176
      and filesize != 828400
      and filesize != 569328
      and filesize != 454656
      and filesize != 531368
      and filesize != 524288
      and filesize != 483328
      and filesize != 713592
      and filesize != 829304
      and filesize != 571256
      and filesize != 774200
      and filesize != 854072
      and filesize != 665144
      and filesize != 774200
      and filesize != 854072
      and filesize != 665144
}

rule SUSP_RTF_Header_Anomaly {
   meta:
      description = "Detects malformed RTF header often used to trick mechanisms that check for a full RTF header"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/975705759618158593"
      date = "2019-01-20"
   condition:
      uint32(0) == 0x74725c7b and /* {\rt */
      not uint8(4) == 0x66 /* not f */
}

rule WEBSHELL_ASPX_ProxyShell_Aug21_1 {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST) and extension"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-servers-are-getting-hacked-via-proxyshell-exploits/"
      date = "2021-08-13"
   condition:
      uint32(0) == 0x4e444221 /* PST header: !BDN */
      and extension == ".aspx"
}
