
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-03
   Identifier: ZeroT CN APT
*/

/* Rule Set ----------------------------------------------------------------- */

rule PP_CN_APT_ZeroT_1 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "09061c603a32ac99b664f7434febfc8c1f9fd7b6469be289bb130a635a6c47c0"
   strings:
      $s1 = "suprise.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule PP_CN_APT_ZeroT_2 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "74eb592ef7f5967b14794acdc916686e061a43169f06e5be4dca70811b9815df"
   strings:
      $s1 = "NO2-2016101902.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule PP_CN_APT_ZeroT_3 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "ee2e2937128dac91a11e9bf55babc1a8387eb16cebe676142c885b2fc18669b2"
   strings:
      $s1 = "/svchost.exe" fullword ascii
      $s2 = "RasTls.dll" fullword ascii
      $s3 = "20160620.htm" fullword ascii
      $s4 = "* $l&$" fullword ascii
      $s5 = "dfjhmh" fullword ascii
      $s6 = "/20160620.htm" fullword ascii
   condition:
      ( uint16(0) == 0x5449 and filesize < 1000KB and 3 of them ) or ( all of them )
}

rule PP_CN_APT_ZeroT_4 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "a9519d2624a842d2c9060b64bb78ee1c400fea9e43d4436371a67cbf90e611b8"
   strings:
      $s1 = "Mcutil.dll" fullword ascii
      $s2 = "mcut.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule PP_CN_APT_ZeroT_5 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "74dd52aeac83cc01c348528a9bcb20bbc34622b156f40654153e41817083ba1d"
   strings:
      $x1 = "dbozcb" fullword ascii

      $s1 = "nflogger.dll" fullword ascii
      $s2 = "/svchost.exe" fullword ascii
      $s3 = "1207.htm" fullword ascii
      $s4 = "/1207.htm" fullword ascii
   condition:
      ( uint16(0) == 0x5449 and filesize < 1000KB and 1 of ($x*) and 1 of ($s*) ) or ( all of them )
}

rule PP_CN_APT_ZeroT_6 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "a16078c6d09fcfc9d6ff7a91e39e6d72e2d6d6ab6080930e1e2169ec002b37d3"
   strings:
      $s1 = "jGetgQ|0h9=" fullword ascii
      $s2 = "\\sfxrar32\\Release\\sfxrar.pdb"
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule PP_CN_APT_ZeroT_7 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "fc2d47d91ad8517a4a974c4570b346b41646fac333d219d2f1282c96b4571478"
   strings:
      $s1 = "RasTls.dll" fullword ascii
      $s2 = "RasTls.exe" fullword ascii
      $s4 = "LOADER ERROR" fullword ascii
      $s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule PP_CN_APT_ZeroT_8 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "4ef91c17b1415609a2394d2c6c353318a2503900e400aab25ab96c9fe7dc92ff"
   strings:
      $s1 = "/svchost.exe" fullword ascii
      $s2 = "RasTls.dll" fullword ascii
      $s3 = "20160620.htm" fullword ascii
      $s4 = "/20160620.htm" fullword ascii
   condition:
      ( uint16(0) == 0x5449 and filesize < 1000KB and 3 of them )
}

rule PP_CN_APT_ZeroT_9 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03"
      hash1 = "a685cf4dca6a58213e67d041bba637dca9cb3ea6bb9ad3eae3ba85229118bce0"
   strings:
      $x1 = "nflogger.dll" fullword ascii
      $s7 = "Zlh.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule CN_APT_ZeroT_nflogger {
   meta:
      description = "Chinese APT by Proofpoint ZeroT RAT  - file nflogger.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-04"
      hash1 = "946adbeb017616d56193a6d43fe9c583be6ad1c7f6a22bab7df9db42e6e8ab10"
   strings:
      $x1 = "\\LoaderDll.VS2010\\Release\\" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule CN_APT_ZeroT_extracted_Go {
   meta:
      description = "Chinese APT by Proofpoint ZeroT RAT  - file Go.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-04"
      hash1 = "83ddc69fe0d3f3d2f46df7e72995d59511c1bfcca1a4e14c330cb71860b4806b"
   strings:
      $x1 = "%s\\cmd.exe /c %s\\Zlh.exe" fullword ascii
      $x2 = "\\BypassUAC.VS2010\\Release\\" fullword ascii

      $s1 = "Zjdsf.exe" fullword ascii
      $s2 = "SS32prep.exe" fullword ascii
      $s3 = "windowsgrep.exe" fullword ascii
      $s4 = "Sysdug.exe" fullword ascii
      $s5 = "Proessz.exe" fullword ascii
      $s6 = "%s\\Zlh.exe" fullword ascii
      $s7 = "/C %s\\%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) or 3 of ($s*) ) ) or ( 7 of them )
}

rule CN_APT_ZeroT_extracted_Mcutil {
   meta:
      description = "Chinese APT by Proofpoint ZeroT RAT  - file Mcutil.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-04"
      hash1 = "266c06b06abbed846ebabfc0e683f5d20dadab52241bc166b9d60e9b8493b500"
   strings:
      $s1 = "LoaderDll.dll" fullword ascii
      $s2 = "QageBox1USER" fullword ascii
      $s3 = "xhmowl" fullword ascii
      $s4 = "?KEYKY" fullword ascii
      $s5 = "HH:mm:_s" fullword ascii
      $s6 = "=licni] has maX0t" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and 3 of them ) or ( all of them )
}

rule CN_APT_ZeroT_extracted_Zlh {
   meta:
      description = "Chinese APT by Proofpoint ZeroT RAT - file Zlh.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-04"
      hash1 = "711f0a635bbd6bf1a2890855d0bd51dff79021db45673541972fe6e1288f5705"
   strings:
      $s1 = "nflogger.dll" fullword wide
      $s2 = "%s %d: CreateProcess('%s', '%s') failed. Windows error code is 0x%08x" fullword ascii
      $s3 = "_StartZlhh(): Executed \"%s\"" fullword ascii
      $s4 = "Executable: '%s' (%s) %i" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}
