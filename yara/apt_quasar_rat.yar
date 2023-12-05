/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-07
   Identifier: Quasar RAT
*/

/* Rule Set ----------------------------------------------------------------- */

rule Quasar_RAT_1 {
   meta:
      description = "Detects Quasar RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      hash1 = "0774d25e33ca2b1e2ee2fafe3fdbebecefbf1d4dd99e6460f0bc8713dd0fd740"
      hash2 = "1ce40a89ef9d56fd32c00db729beecc17d54f4f7c27ff22f708a957cd3f9a4ec"
      hash3 = "515c1a68995557035af11d818192f7866ef6a2018aa13112fefbe08395732e89"
      hash4 = "f08db220df716de3d4f63f3007a03f902601b9b32099d6a882da87312f263f34"
      id = "36220de3-aa1a-5c34-adae-432d939c811e"
   strings:
      $s1 = "DoUploadAndExecute" fullword ascii
      $s2 = "DoDownloadAndExecute" fullword ascii
      $s3 = "DoShellExecute" fullword ascii
      $s4 = "set_Processname" fullword ascii

      $op1 = { 04 1e fe 02 04 16 fe 01 60 }
      $op2 = { 00 17 03 1f 20 17 19 15 28 }
      $op3 = { 00 04 03 69 91 1b 40 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and all of ($s*) or all of ($op*) )
}

rule Quasar_RAT_2 {
   meta:
      description = "Detects Quasar RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      super_rule = 1
      hash1 = "0774d25e33ca2b1e2ee2fafe3fdbebecefbf1d4dd99e6460f0bc8713dd0fd740"
      hash2 = "515c1a68995557035af11d818192f7866ef6a2018aa13112fefbe08395732e89"
      hash3 = "f08db220df716de3d4f63f3007a03f902601b9b32099d6a882da87312f263f34"
      id = "0ca795c5-3631-5a99-8675-37558485f478"
   strings:
      $x1 = "GetKeyloggerLogsResponse" fullword ascii
      $x2 = "get_Keylogger" fullword ascii
      $x3 = "HandleGetKeyloggerLogsResponse" fullword ascii

      $s1 = "DoShellExecuteResponse" fullword ascii
      $s2 = "GetPasswordsResponse" fullword ascii
      $s3 = "GetStartupItemsResponse" fullword ascii
      $s4 = "<GetGenReader>b__7" fullword ascii
      $s5 = "RunHidden" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and $x1 ) or ( all of them )
}

rule MAL_QuasarRAT_May19_1 {
   meta:
      description = "Detects QuasarRAT malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.ensilo.com/uncovering-new-activity-by-apt10"
      date = "2019-05-27"
      modified = "2023-01-06"
      hash1 = "0644e561225ab696a97ba9a77583dcaab4c26ef0379078c65f9ade684406eded"
      id = "a4e82b6a-31f8-59fc-acfa-805c4594680a"
   strings:
      $x1 = "Quasar.Common.Messages" ascii fullword
      $x2 = "Client.MimikatzTools" ascii fullword
      $x3 = "Resources.powerkatz_x86.dll" ascii fullword
      $x4 = "Uninstalling... good bye :-(" wide

      $xc1 = { 41 00 64 00 6D 00 69 00 6E 00 00 11 73 00 63 00
               68 00 74 00 61 00 73 00 6B 00 73 00 00 1B 2F 00
               63 00 72 00 65 00 61 00 74 00 65 00 20 00 2F 00
               74 00 6E 00 20 00 22 00 00 27 22 00 20 00 2F 00
               73 }
      $xc2 = { 00 70 00 69 00 6E 00 67 00 20 00 2D 00 6E 00 20
               00 31 00 30 00 20 00 6C 00 6F 00 63 00 61 00 6C
               00 68 00 6F 00 73 00 74 00 20 00 3E 00 20 00 6E
               00 75 00 6C 00 0D 00 0A 00 64 00 65 00 6C 00 20
               00 2F 00 61 00 20 00 2F 00 71 00 20 00 2F 00 66
               00 20 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and 1 of them
}
