/*

   Generic Anomalies

   Florian Roth
   Nextron Systems GmbH

	License: Detetction Rule License 1.1 (https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md)

*/

/* Performance killer - value isn't big enough
rule Embedded_EXE_Cloaking {
        meta:
                description = "Detects an embedded executable in a non-executable file"
                license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
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
*/

// whitelist-approach failed : reworked in SUSP_Known_Type_Cloaked_as_JPG

// rule Cloaked_as_JPG {
//    meta:
//       description = "Detects a non-JPEG file cloaked as JPG"
//       author = "Florian Roth (Nextron Systems)"
//       date = "2015/03/02"
//       modified = "2022-09-16"
//       score = 40
//    strings:
//       $fp1 = "<!DOCTYPE" ascii
//       $fp2 = "Sophos Encrypted File Format" ascii
//       $fp3 = "This is a critical resource file used by WatchGuard/TDR" ascii
//    condition:
//       uint16be(0) != 0xFFD8 and extension == ".jpg"
//       and filetype != "GIF"
//       and filetype != "PDF"
//       and not $fp1 in (0..30)
//       and not $fp2 at 0
//       and not $fp3
//       and not uint16(0) == 0x8b1f /* GZIP */
//       and not uint16(0) == 0x4d42 /* BMP */
//       and not uint32(0) == 0x474E5089 /* PNG Header */
//       and not uint32(0) == 0x002A4949 /* TIFF Header */
//       and not uint32be(0) == 0x3c737667 /* <svg */
//       and not uint32be(0) == 0x52494646 /* RIFF (WebP) */
//       and not uint32be(0x4) == 0x66747970 /* HEIF Header https://github.com/strukturag/libheif/commit/6ca8e2548dbfe21200bae3a7c2c315a1796e3852 */
//       and not uint32be(0xe) == 0x4a464946 /* JFIF distributed by Matlab */
//       and not filename matches /\$[Ii][A-Z0-9]{6}/
//       and not filepath contains "WinSxS"
//       and not filepath contains "Package_for_RollupFix"
//       and not filename matches /^\._/
//       and not filepath contains "$Recycle.Bin"
//       and not filepath contains "\\Cache\\" /* generic cache e.g. for Chrome: \User Data\Default\Cache\ */
//       and not filepath contains "\\User Data\\Default\\Extensions\\" // chrome extensions
//       and not filepath contains "\\cache2\\" // FF cache
//       and not filepath contains "\\Microsoft\\Windows\\INetCache\\IE\\" // old IE
//       and not filepath contains "/com.apple.Safari/WebKitCache/"
//       and not filepath contains "\\Edge\\User Data\\" // some uncommon Edge path
//       and not filepath contains "/Code/"
//       and not filepath contains "\\Code\\"
// }

rule SUSP_Known_Type_Cloaked_as_JPG {
   meta:
      description = "Detects a non-JPEG file type cloaked as .jpg"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - replacement for Cloaked_as_JPG rule"
      date = "2022-09-16"
      score = 60
      id = "728908a6-74cf-5bab-a23f-cd03ed209430"
   condition:
      (extension == ".jpg" or extension == ".jpeg") and (
         filetype == "EXE" or
         filetype == "ELF" or
         filetype == "MACH-O" or
         filetype == "VBS" or
         filetype == "PHP" or
         filetype == "JSP" or
         filetype == "Python" or
         filetype == "LSASS Dump File" or
         filetype == "ASP" or
         filetype == "BATCH" or
         filetype == "RTF" or
         filetype == "MDMP" or

         filetype contains "PowerShell" or
         filetype contains "Base64"
      )
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
      author = "Florian Roth (Nextron Systems)"
      score = 60
      nodeepdive = 1
      date = "2015-12-21"
      modified = "2022-04-27"
      noarchivescan = 1
      id = "408bdb95-3b15-5f4e-a948-949ea4ce0477"
   strings:
      $fp = "Wine placeholder DLL"
   condition:
      uint16(0) == 0x5a4d
      and filename == "explorer.exe"
      and not filepath contains "teamviewer"
      and not filepath contains "/lib/wine/fakedlls"
      and (filesize < 800KB or filesize > 6500KB)
      and not $fp
}

rule Suspicious_Size_chrome_exe {
   meta:
      description = "Detects uncommon file size of chrome.exe"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      nodeepdive = 1
      date = "2015-12-21"
      modified = "2022-09-15"
      noarchivescan = 1
      id = "f164394a-5c02-5056-aceb-044ee118578d"
   strings:
      $fp1 = "HP Sure Click Chromium Launcher" wide
      $fp2 = "BrChromiumLauncher.exe" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filename == "chrome.exe"
      and (filesize < 500KB or filesize > 5000KB)
      and not 1 of ($fp*)
}

rule Suspicious_Size_csrss_exe {
   meta:
      description = "Detects uncommon file size of csrss.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      modified = "2022-01-28"
      noarchivescan = 1
      id = "5a247b51-6c91-5753-95b3-4a4c2b2286eb"
   condition:
      uint16(0) == 0x5a4d
      and filename == "csrss.exe"
      and (filesize > 50KB)
}

rule Suspicious_Size_iexplore_exe {
   meta:
      description = "Detects uncommon file size of iexplore.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      noarchivescan = 1
      id = "d097a599-0fad-574f-8281-46c910e8e54d"
   condition:
      uint16(0) == 0x5a4d
      and filename == "iexplore.exe"
      and not filepath contains "teamviewer"
      and (filesize < 75KB or filesize > 910KB)
}

rule Suspicious_Size_firefox_exe {
   meta:
      description = "Detects uncommon file size of firefox.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      modified = "2024-06-03"
      noarchivescan = 1
      id = "73c4b838-9277-5756-a35d-4a644be5ad5d"
   condition:
      uint16(0) == 0x5a4d
      and filename == "firefox.exe"
      and (filesize < 265KB or filesize > 910KB)
      and not filepath contains "Malwarebytes"
}

rule Suspicious_Size_java_exe {
   meta:
      description = "Detects uncommon file size of java.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      noarchivescan = 1
      id = "b6dc297b-8388-5e39-ba77-c027cdea7afa"
   condition:
      uint16(0) == 0x5a4d
      and filename == "java.exe"
      and (filesize < 30KB or filesize > 900KB)
}

rule Suspicious_Size_lsass_exe {
   meta:
      description = "Detects uncommon file size of lsass.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      noarchivescan = 1
      id = "005661c7-7576-5c13-9534-b49c12b2faad"
   condition:
      uint16(0) == 0x5a4d
      and filename == "lsass.exe"
      and (filesize < 10KB or filesize > 100KB)
}

rule Suspicious_Size_svchost_exe {
   meta:
      description = "Detects uncommon file size of svchost.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      noarchivescan = 1
      id = "31a8d00e-ebfc-5001-9c58-d3a2580f16b3"
   condition:
      uint16(0) == 0x5a4d
      and filename == "svchost.exe"
      and (filesize < 14KB or filesize > 100KB)
}

rule Suspicious_Size_winlogon_exe {
   meta:
      description = "Detects uncommon file size of winlogon.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      noarchivescan = 1
      id = "8665e8d0-3b5f-5227-8879-cdd614123439"
   condition:
      uint16(0) == 0x5a4d
      and filename == "winlogon.exe"
      and (filesize < 279KB or filesize > 970KB)
}

rule Suspicious_Size_igfxhk_exe {
   meta:
      description = "Detects uncommon file size of igfxhk.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-21"
      modified = "2022-03-08"
      noarchivescan = 1
      id = "18cc167a-3e65-567f-adcf-d2d311520c1d"
   condition:
      uint16(0) == 0x5a4d
      and filename == "igfxhk.exe"
      and (filesize < 200KB or filesize > 300KB)
}

rule Suspicious_Size_servicehost_dll {
   meta:
      description = "Detects uncommon file size of servicehost.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      noarchivescan = 1
      id = "ac71393c-a475-59e0-b22a-d5ee3d25084b"
   condition:
      uint16(0) == 0x5a4d
      and filename == "servicehost.dll"
      and filesize > 150KB
}

rule Suspicious_Size_rundll32_exe {
   meta:
      description = "Detects uncommon file size of rundll32.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      noarchivescan = 1
      id = "5b9feae7-17d8-56e4-870a-ef865f2d09bf"
   condition:
      uint16(0) == 0x5a4d
      and filename == "rundll32.exe"
      and (filesize < 30KB or filesize > 120KB)
}

rule Suspicious_Size_taskhost_exe {
   meta:
      description = "Detects uncommon file size of taskhost.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      modified = "2024-06-10"
      noarchivescan = 1
      id = "71b6c853-f490-5d5a-b481-909f6f3a8798"
   condition:
      uint16(0) == 0x5a4d
      and filename == "taskhost.exe"
      and not filepath contains "/lib/wine/fakedlls"
      and (filesize < 45KB or filesize > 200KB)
}

rule Suspicious_Size_spoolsv_exe {
   meta:
      description = "Detects uncommon file size of spoolsv.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      modified = "2025-03-17"
      noarchivescan = 1
      id = "14bb3463-b99f-57e1-8cff-fe9a34771093"
   condition:
      uint16(0) == 0x5a4d
      and filename == "spoolsv.exe"
      and (filesize < 50KB or filesize > 1500KB)
}

rule Suspicious_Size_smss_exe {
   meta:
      description = "Detects uncommon file size of smss.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      noarchivescan = 1
      id = "7bdc8953-9240-5d22-b2a6-fe95fbc101c2"
   condition:
      uint16(0) == 0x5a4d
      and filename == "smss.exe"
      and (filesize < 40KB or filesize > 5000KB)
}

rule Suspicious_Size_wininit_exe {
   meta:
      description = "Detects uncommon file size of wininit.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "2015-12-23"
      noarchivescan = 1
      id = "7b58f497-f214-5bf3-8a5c-8edb52749d09"
      modified = "2025-08-13"
   condition:
      uint16(0) == 0x5a4d
      and filename == "wininit.exe"
      and (filesize < 50KB or filesize > 1MB)
}

rule Suspicious_AutoIt_by_Microsoft {
   meta:
      description = "Detects a AutoIt script with Microsoft identification"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - VT"
      date = "2017-12-14"
      score = 60
      hash1 = "c0cbcc598d4e8b501aa0bd92115b4c68ccda0993ca0c6ce19edd2e04416b6213"
      id = "69b1c93d-ab12-5fdc-b6eb-fb135796d3a9"
   strings:
      $s1 = "Microsoft Corporation. All rights reserved" fullword wide
      $s2 = "AutoIt" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule SUSP_Size_of_ASUS_TuningTool {
   meta:
      description = "Detects an ASUS tuning tool with a suspicious size"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17"
      modified = "2022-12-21"
      score = 60
      noarchivescan = 1
      hash1 = "d4e97a18be820a1a3af639c9bca21c5f85a3f49a37275b37fd012faeffcb7c4a"
      id = "d22a1bf9-55d6-5cb4-9537-ad13b23af4d1"
   strings:
      $s1 = "\\Release\\ASGT.pdb" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and filesize > 70KB and all of them
}

rule SUSP_PiratedOffice_2007 {
   meta:
      description = "Detects an Office document that was created with a pirated version of MS Office 2007"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/pwnallthethings/status/743230570440826886?lang=en"
      date = "2018-12-04"
      score = 40
      hash1 = "210448e58a50da22c0031f016ed1554856ed8abe79ea07193dc8f5599343f633"
      id = "b36e9a59-7617-503b-968d-5b6b72b227ea"
   strings:
      $s7 = "<Company>Grizli777</Company>" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 300KB and all of them
}

rule SUSP_Scheduled_Task_BigSize {
   meta:
      description = "Detects suspiciously big scheduled task XML file as seen in combination with embedded base64 encoded PowerShell code"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-12-06"
      id = "61b07b30-1058-5a53-99e7-2c48ec9d23b5"
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
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-01-07"
      modified = "2022-06-30"
      score = 50
      hash1 = "e5e89bdff733d6db1cffe8b3527e823c32a78076f8eadc2f9fd486b74a0e9d88"
      hash2 = "ce4c1b718b54973291aefdd63d1cca4e4d8d4f5353a2be7f139a290206d0c170"
      hash3 = "adb72ea4eab7b2efc2da6e72256b5a3bb388e9cdd4da4d3ff42a9fec080aa96f"
      hash4 = "1c0bd6660fa43fa90bd88b56cdd4a4c2ffb4ef9d04e8893109407aa7039277db"
      id = "576b118c-d4be-5ce2-994a-ce3f943dda88"
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
      and filesize != 640000  /* putty provided by Safenet https://thalesdocs.com/gphsm/luna/7.1/docs/network/Content/install/sa_hw_install/hardware_installation_lunasa.htm */
      and filesize != 650720  /* Citrix XenCenter */
      and filesize != 662808  /* Citrix XenCenter */
      and filesize != 651256  /* Citrix XenCenter */
      and filesize != 664432  /* Citrix XenCenter */
}

rule SUSP_RTF_Header_Anomaly {
   meta:
      description = "Detects malformed RTF header often used to trick mechanisms that check for a full RTF header"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/ItsReallyNick/status/975705759618158593"
      date = "2019-01-20"
      modified = "2022-09-15"
      score = 50
      id = "fb362640-9a45-5ee5-8749-3980e0549932"
   condition:
      uint32(0) == 0x74725c7b and  /* {\rt */
      not uint8(4) == 0x66  /* not f */
}

rule WEBSHELL_ASPX_ProxyShell_Aug21_1 {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST) and extension"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-servers-are-getting-hacked-via-proxyshell-exploits/"
      date = "2021-08-13"
      id = "8f01cbda-b1cf-5556-9f6a-e709df6dadb2"
   condition:
      uint32(0) == 0x4e444221  /* PST header: !BDN */
      and extension == ".aspx"
}
