/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-29
   Identifier: GRIZZLY STEPPE
*/

/* Rule Set ----------------------------------------------------------------- */

rule GRIZZLY_STEPPE_Malware_1 {
   meta:
      description = "Auto-generated rule - file HRDG022184_certclint.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/WVflzO"
      date = "2016-12-29"
      hash1 = "9f918fb741e951a10e68ce6874b839aef5a26d60486db31e509f8dcaa13acec5"
      id = "7239a5f3-9c29-57d7-be95-946d14039353"
   strings:
      $s1 = "S:\\Lidstone\\renewing\\HA\\disable\\In.pdb" fullword ascii
      $s2 = "Repeat last find command)Replace specific text with different text" fullword wide
      $s3 = "l\\Processor(0)\\% Processor Time" fullword wide
      $s6 = "Self Process" fullword wide
      $s7 = "Default Process" fullword wide
      $s8 = "Star Polk.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 4 of them )
}

rule GRIZZLY_STEPPE_Malware_2 {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/WVflzO"
      date = "2016-12-29"
      hash1 = "9acba7e5f972cdd722541a23ff314ea81ac35d5c0c758eb708fb6e2cc4f598a0"
      hash2 = "55058d3427ce932d8efcbe54dccf97c9a8d1e85c767814e34f4b2b6a6b305641"
      id = "37cfba67-af85-5efe-9b07-9f1e5d9f9195"
   strings:
      $x1 = "GoogleCrashReport.dll" fullword ascii

      $s1 = "CrashErrors" fullword ascii
      $s2 = "CrashSend" fullword ascii
      $s3 = "CrashAddData" fullword ascii
      $s4 = "CrashCleanup" fullword ascii
      $s5 = "CrashInit" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and $x1 ) or ( all of them )
}

rule PAS_TOOL_PHP_WEB_KIT_mod {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://www.us-cert.gov/security-publications/GRIZZLY-STEPPE-Russian-Malicious-Cyber-Activity"
      author = "US CERT - modified by Florian Roth due to performance reasons"
      date = "2016/12/29"
      id = "6bc75e44-7784-5e48-9bbc-052d84ebee83"
   strings:
      $php = "<?php"
      $base64decode1 = "='base'.("
      $strreplace = "str_replace(\"\\n\", ''"
      $md5 = ".substr(md5(strrev("
      $gzinflate = "gzinflate"
      $cookie = "_COOKIE"
      $isset = "isset"
   condition:
      uint32(0) == 0x68703f3c and
      $php at 0 and
      (filesize > 10KB and filesize < 30KB) and
      #cookie == 2 and
      #isset == 3 and
      all of them
}

rule WebShell_PHP_Web_Kit_v3 {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://github.com/wordfence/grizzly"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "2016/01/01"
      id = "dc5fa2c9-3e1e-594d-be4f-141e1f4915f1"
   strings:
      $php = "<?php $"
      $php2 = "@assert(base64_decode($_REQUEST["

      $s1 = "(str_replace(\"\\n\", '', '"
      $s2 = "(strrev($" ascii
      $s3 = "de'.'code';" ascii
   condition:
      ( ( uint32(0) == 0x68703f3c and $php at 0 ) or $php2 ) and
      filesize > 8KB and filesize < 100KB and
      all of ($s*)
}

rule WebShell_PHP_Web_Kit_v4 {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://github.com/wordfence/grizzly"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "2016/01/01"
      id = "a5f915cd-b9c5-5cd3-b0a2-c15f6124737a"
   strings:
      $php = "<?php $"

      $s1 = "(StR_ReplAcE(\"\\n\",'',"
      $s2 = ";if(PHP_VERSION<'5'){" ascii
      $s3 = "=SuBstr_rePlACe(" ascii
   condition:
      uint32(0) == 0x68703f3c and 
      $php at 0 and
      filesize > 8KB and filesize < 100KB and
      2 of ($s*)
}



rule APT_APT29_wellmess_dotnet_unique_strings {
   meta:
      description = "Rule to detect WellMess .NET samples based on unique strings and function/variable names"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "2285a264ffab59ab5a1eb4e2b9bcab9baf26750b6c551ee3094af56a4442ac41"
      id = "7a058ec7-f795-5226-b511-ff469a969ee6"
   strings:
      $s1 = "HealthInterval" wide
      $s2 = "Hello from Proxy" wide 
      $s3 = "Start bot:" wide
      $s4 = "FromNormalToBase64" ascii 
      $s5 = "FromBase64ToNormal" ascii 
      $s6 = "WellMess" ascii
   condition:
      uint16(0) == 0x5a4d and uint16(uint16(0x3c)) == 0x4550 and 3 of them
}

rule APT_APT29_sorefang_encryption_key_schedule { 
   meta:
      description = "Rule to detect SoreFang based on the key schedule used for encryption"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "8d89edc1-a9fc-5155-9dc2-8d7f952f90d1"
   strings:
      $ = { C7 05 ?? ?? ?? ?? 63 51 E1 B7 B8 ?? ?? ?? ?? 8B 48 
            FC 81 E9 47 86 C8 61 89 08 83 C0 04 3D ?? ?? ?? ?? 
            7E EB 33 D2 33 C9 B8 2C 00 00 00 89 55 D4 33 F6 89 
            4D D8 33 DB 3B F8 0F 4F C7 8D 04 40 89 45 D0 83 F8 
            01 7C 4F 0F 1F 80 00 00 00 00 }
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and any of them 
}

rule APT_APT29_sorefang_encryption_key_2b62 {
  meta:
      description = "Rule to detect SoreFang based on hardcoded encryption key"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "9a7abad7-1cfa-52c8-9416-47cb80486714"
   strings:
      $ = "2b6233eb3e872ff78988f4a8f3f6a3ba"
   condition:
      ( uint16(0) == 0x5A4D and uint16(uint32(0x3c) ) == 0x4550) 
      and any of them 
}

rule APT_APT29_sorefang_directory_enumeration_output_strings { 
   meta:
      description = "Rule to detect SoreFang based on formatted string output for directory enumeration"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "e24dbda1-3d43-52a7-9249-70a648f4913e"
   strings:
      $ = "----------All usres directory----------" 
      $ = "----------Desktop directory----------"
      $ = "----------Documents directory----------"
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) 
      and 2 of them 
}

rule APT_APT29_sorefang_command_elem_cookie_ga_boundary_string { 
   meta:
      description = "Rule to detect SoreFang based on scheduled task element and Cookie header/boundary strings"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "3c6ffbad-9b39-5518-aa66-d76531ddb9ea"
   strings:
      $ = "<Command>" wide
      $ = "Cookie:_ga="
      $ = "------974767299852498929531610575"
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) 
      and 2 of them 
}

rule APT_APT29_sorefang_encryption_round_function { 
   meta:
      description = "Rule to detect SoreFang based on the encryption round function"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "0be1c084-c8df-5920-a320-90364a7fb542"
   strings:
      $ = { 8A E9 8A FB 8A 5D 0F 02 C9 88 45 0F FE C1 0F BE C5 88 6D F3 8D
            14 45 01 00 00 00 0F AF D0 0F BE C5 0F BE C9 0F AF C8 C1 FA 1B C0 E1 05 0A D1 8B 4D EC 0F BE C1 89 55 E4 8D 14 45 01 00 00 00 0F AF D0 8B C1}
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550)
      and any of them 
}

rule APT_APT29_sorefang_add_random_commas_spaces { 
   meta:
      description = "Rule to detect SoreFang based on function that adds commas and spaces"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "9a89c619-6309-500f-b4dc-c8a3e8fc4417"
   strings:
      $ = { E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 8B CE 83 FA 04 7E 09 6A
            02 68 ?? ?? ?? ?? EB 07 6A 01 68 } 
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) 
      and any of them
}

rule APT_APT29_sorefang_modify_alphabet_custom_encode { 
   meta:
      description = "Rule to detect SoreFang based on arguments passed into custom encoding algorithm function"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "7c5c1be0-ccad-5c8f-a026-445994b1f279"
   strings:
      $ = { 33 C0 8B CE 6A 36 6A 71 66 89 46 60 88 46 62 89 46 68 66 89 46
            64 }
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and any of them
}

rule APT_APT29_sorefang_custom_encode_decode {
   meta:
      description = "Rule to detect SoreFang based on the custom encoding/decoding algorithm function"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "4885a659-bb3a-5e33-99cc-b827931bf58f"
   strings:
      $ = { 55 8B EC 8B D1 53 56 8B 75 08 8B DE 80 42 62 FA 8A 4A 62 66 D3
            EB 57 3A 5A 5C 74 0F}
      $ = { 3A 5A 5D 74 0A 3A 5A 58 74 05 3A 5A 59 75 05 FE C1 88 4A 62 8A 
            4A 62 B8 01 00 00 00}
      $ = { 8A 46 62 84 C0 74 3E 3C 06 73 12 0F B6 C0 B9 06 00 00 00 2B C8 
            C6 46 62 06 66 D3 66 60 0F B7 4E 60}
      $ = { 80 3C 38 0D 0F 84 93 01 00 00 C6 42 62 06 8B 56 14 83 FA 10 72 
            04 8B 06}
      $ = { 0F BE 0C 38 8B 45 EC 0F B6 40 5B 3B C8 75 07 8B 55 EC B3 3E}
      $ = { 0F BE 0C 38 8B 45 EC 0F B6 40 5E 3B C8 75 0B 8B 55 EC D0 EB C6 
            42 62 05}
      $ = { 8B 55 EC 0F BE 04 38 0F B6 DB 0F B6 4A 5F 3B C1 B8 3F 00 00 00 
            0F 44 D8}
      $ = { 8A 4A 62 66 8B 52 60 66 D3 E2 0F B6 C3 66 0B D0 8B 45 EC 66 89 
            50 60 8A 45 F3 02 C1 88 45 F3 3C 08 72 2E 04 F8 8A C8 88 45 F3 
            66 D3 EA 8B 4D 08 0F B6 C2 50 }
      $ = { 3A 5A 5C 74 0F 3A 5A 5D 74 0A 3A 5A 58 74 05 3A 5A 59 75 05 FE 
            C1 88 4A 62 }
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) 
      and any of them 
}

rule APT_APT29_sorefang_remove_chars_comma_space_dot { 
   meta:
      description = "Rule to detect SoreFang based on function that removes commas, spaces and dots"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
      id = "c15779b0-6a5e-5345-94ad-95615b567f1f"
   strings:
      $ = {8A 18 80 FB 2C 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08} 
      $ = {8A 18 80 FB 2E 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08} 
      $ = {8A 18 80 FB 20 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08}
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them 
}

rule APT_APT29_sorefang_disk_enumeration_strings { 
   meta:
      description = "Rule to detect SoreFang based on disk enumeration strings"
      author = "NCSC"
      reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
      hash = "a4b790ddffb3d2e6691dcacae08fb0bfa1ae56b6c73d70688b097ffa831af064" 
      id = "0ff01793-6fb7-5cff-b4e4-6709269ab0f0"
   strings:
      $ = "\x0D\x0AFree on disk: "
      $ = "Total disk: "
      $ = "Error in GetDiskFreeSpaceEx\x0D\x0A"
      $ = "\x0D\x0AVolume label: "
      $ = "Serial number: "
      $ = "File system: "
      $ = "Error in GetVolumeInformation\x0D\x0A"
      $ = "I can not het information about this disk\x0D\x0A"
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) 
      and all of them 
}

