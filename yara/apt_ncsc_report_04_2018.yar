/*
   Yara Rule Set
   Author: NCSC (modified for performance reasons by Florian Roth)
   Date: 2018-04-06
   Identifier: Hostile state actors compromising UK organisations
   Reference: https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control
*/

rule Bytes_used_in_AES_key_generation {
   meta:
      author = "NCSC"
      description = "Detects Backdoor.goodor"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
   strings:
      $a1 = {35 34 36 35 4B 4A 55 54 5E 49 55 5F 29 7B 68 36 35 67 34 36 64 66 35 68}
      /* $a2 = {fb ff ff ff 00 00}  disabled due to performance issues */
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and all of ($a*)
}

rule Partial_Implant_ID {
   meta:
      author = "NCSC"
      description = "Detects implant from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
   strings:
      $a1 = {38 38 31 34 35 36 46 43}
      /* $a2 = {fb ff ff ff 00 00} disabled due to performance issues */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of ($a*)
}

rule Sleep_Timer_Choice {
   meta:
      author = "NCSC"
      description = "Detects malware from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
   strings:
      $a1 = {8b0424b90f00000083f9ff743499f7f98d420f}
      /* $a2 = {fb ff ff ff 00 00} disabled due to performance issues */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of ($a*)
}

rule User_Function_String {
   meta:
      author = "NCSC"
      description = "Detects user function string from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
   strings:
      /* $b1 = {fb ff ff ff 00 00} disabled due to performance issues */
      $a2 = "e.RandomHashString"
      $a3 = "e.Decode"
      $a4 = "e.Decrypt"
      $a5 = "e.HashStr"
      $a6 = "e.FromB64"
   condition:
      /* $b1 and */ 4 of ($a*)
}

rule generic_shellcode_downloader_specific {
  meta:
    author = "NCSC"
    description = "Detects Doorshell from NCSC report"
    reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
    date = "2018/04/06"
    hash = "b8bc0611a7fd321d2483a0a9a505251e15c22402e0cfdc62c0258af53ed3658a"
  strings:
    $push1 = {68 6C 6C 6F 63}
    $push2 = {68 75 61 6C 41}
    $push3 = {68 56 69 72 74}
    $a = {BA 90 02 00 00 46 C1 C6 19 03 DD 2B F4 33 DE}
    $b = {87 C0 81 F2 D1 19 89 14 C1 C8 1F FF E0}
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3C)) == 0x4550) and ($a or $b) and @push1 < @push2 and @push2 < @push3
}

rule Batch_Script_To_Run_PsExec {
   meta:
      author = "NCSC"
      description = "Detects malicious batch file from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "b7d7c4bc8f9fd0e461425747122a431f93062358ed36ce281147998575ee1a18"
   strings:
      $ = "Tokens=1 delims=" ascii
      $ = "SET ws=%1" ascii
      $ = "Checking %ws%" ascii
      $ = "%TEMP%\\%ws%ns.txt" ascii
      $ = "ps.exe -accepteula" ascii
   condition:
      3 of them
}

rule Batch_Powershell_Invoke_Inveigh {
   meta:
      author = "NCSC"
      description = "Detects malicious batch file from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "0a6b1b29496d4514f6485e78680ec4cd0296ef4d21862d8bf363900a4f8e3fd2"
   strings:
      $ = "Inveigh.ps1" ascii
      $ = "Invoke-Inveigh" ascii
      $ = "-LLMNR N -HTTP N -FileOutput Y" ascii
      $ = "powershell.exe" ascii
   condition:
      all of them
}

rule lnk_detect {
   meta:
      author = "NCSC"
      description = "Detects malicious LNK file from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
   strings:
      $lnk_magic = {4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46}
      $lnk_target = {41 00 55 00 54 00 4F 00 45 00 58 00 45 00 43 00 2E 00 42 00 41 00 54}
      $s1 = {5C 00 5C 00 31 00}
      $s2 = {5C 00 5C 00 32 00}
      $s3 = {5C 00 5C 00 33 00}
      $s4 = {5C 00 5C 00 34 00}
      $s5 = {5C 00 5C 00 35 00}
      $s6 = {5C 00 5C 00 36 00}
      $s7 = {5C 00 5C 00 37 00}
      $s8 = {5C 00 5C 00 38 00}
      $s9 = {5C 00 5C 00 39 00}
   condition:
      uint32be(0) == 0x4c000000 and
      uint32be(4) == 0x01140200 and
      (($lnk_magic at 0) and $lnk_target) and 1 of ($s*)
}

rule RDP_Brute_Strings {
   meta:
      author = "NCSC"
      description = "Detects RDP brute forcer from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "8234bf8a1b53efd2a452780a69666d1aedcec9eb1bb714769283ccc2c2bdcc65"
   strings:
      $ = "RDP Brute" ascii wide
      $ = "RdpChecker" ascii
      $ = "RdpBrute" ascii
      $ = "Brute_Count_Password" ascii
      $ = "BruteIPList" ascii
      $ = "Chilkat_Socket_Key" ascii
      $ = "Brute_Sync_Stat" ascii
      $ = "(Error! Hyperlink reference not valid.)" wide
      $ = "BadRDP" wide
      $ = "GoodRDP" wide
      $ = "@echo off{0}:loop{0}del {1}{0}if exist {1} goto loop{0}del {2}{0}del \"{2}\"" wide
      $ = "Coded by z668" wide
   condition:
      4 of them
}

rule Z_WebShell {
   meta:
      author = "NCSC"
      description = "Detects Z Webshell from NCSC report"
      reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
      date = "2018/04/06"
      hash = "ace12552f3a980f1eed4cadb02afe1bfb851cafc8e58fb130e1329719a07dbf0"
   strings:
      $ = "Z_PostBackJS" ascii wide
      $ = "z_file_download" ascii wide
      $ = "z_WebShell" ascii wide
      $ = "1367948c7859d6533226042549228228" ascii wide
   condition:
      3 of them
}
