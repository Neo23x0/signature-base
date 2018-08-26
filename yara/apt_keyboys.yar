/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-11-02
   Identifier: Keyboys
   Reference: http://www.pwc.co.uk/issues/cyber-security-data-privacy/research/the-keyboys-are-back-in-town.html
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule KeyBoys_malware_1 {
   meta:
      description = "Detects Keyboys malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.pwc.co.uk/issues/cyber-security-data-privacy/research/the-keyboys-are-back-in-town.html"
      date = "2017-11-02"
      hash1 = "1d716cee0f318ee14d7c3b946a4626a1afe6bb47f69668065e00e099be362e22"
      hash2 = "a6e9951583073ab2598680b17b8b99bab280d6dca86906243bafaf3febdf1565"
      hash3 = "34f740e5d845710ede1d942560f503e117600bcc7c5c17e03c09bfc66556196c"
      hash4 = "750f4a9ae44438bf053ffb344b959000ea624d1964306e4b3806250f4de94bc8"
      hash5 = "fc84856814307a475300d2a44e8d15635dedd02dc09a088a47d1db03bc309925"
      hash6 = "0f9a7efcd3a2b1441834dae7b43cd8d48b4fc1daeb2c081f908ac5a1369de753"
   strings:
      $x1 = "reg add HKLM\\%s\\Parameters /v ServiceDll /t REG_EXPAND_SZ /d \"%s\" /f" fullword ascii
      $x3 = "Internet using \\svchost.exe -k  -n 3" fullword ascii
      $x4 = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v SFCDisable /t REG_DWORD /d 4 /f" fullword ascii

      $s1 = "sc create %s binpath= \"%s\" Type= share Start= auto DisplayName= \"%s\"" fullword ascii
      $s2 = "ExecCmd:%s" fullword ascii
      $s3 = "szCommand : %s" fullword ascii
      $s4 = "Current user is a member of the %s\\%s group" fullword ascii
      $s5 = "icacls %s /grant administrators:F" fullword ascii
      $s6 = "Ping 127.0.0.1 goto Repeat" fullword ascii
      $s7 = "Start MoveFile %s -> %s" fullword ascii
      $s8 = "move %s\\dllcache%s %s\\dllcache\\%s" fullword ascii
      $s9 = "%s\\cmd.exe /c \"%s\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and (
         pe.imphash() == "68f7eced34c46808756db4b0c45fb589" or
         ( pe.exports("Insys") and pe.exports("Inuser") and pe.exports("SSSS") ) or
         1 of ($x*) or
         4 of them
      )
}

/* Update March 2018 */

rule KeyBoy_InstallClient {
   meta:
      description = "Detects KeyBoy InstallClient"
      author = "Markus Neis, Florian Roth"
      reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/tropic-trooper-new-strategy/"
      date = "2018-03-26"
      hash1 = "85d32cb3ae046a38254b953a00b37bb87047ec435edb0ce359a867447ee30f8b"
      hash2 = "b0f120b11f727f197353bc2c98d606ed08a06f14a1c012d3db6fe0a812df528a"
      hash1 = "d65f809f7684b28a6fa2d9397582f350318027999be3acf1241ff44d4df36a3a"
   strings:
      $x1 = "egsvr32.exe \"/u bitsadmin /canceft\\windows\\currebitsadmin" ascii
      $x2 = "/addfibitsadmin /Resumbitsadmin /SetNosoftware\\microsotifyCmdLine " ascii
      $x3 = "D:\\Work\\Project\\VS\\house\\Apple\\" ascii
      $x4 = "Bj+I11T6z9HFMG5Z5FMT/u62z9zw8FyWV0xrcK7HcYXkiqnAy5tc/iJuKtwM8CT3sFNuQu8xDZQGSR6D8/Bc/Dpuz8gMJFz+IrYqNAzwuPIitg==" fullword ascii
      $x5 = "szCmd1:%s" fullword ascii

      $s1 = "cmd.exe /c \"%s\"" fullword ascii
      $s4 = "rundll32.exe %s Main" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($x*) or 2 of them )
}

rule KeyBoy_wab32res {
   meta:
      description = "Detects KeyBoy Loader wab32res.dll"
      author = "Markus Neis, Florian Roth"
      reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/tropic-trooper-new-strategy/"
      date = "2018-03-26"
      hash1 = "02281e26e89b61d84e2df66a0eeb729c5babd94607b1422505cd388843dd5456"
      hash2 = "fb9c9cbf6925de8c7b6ce8e7a8d5290e628be0b82a58f3e968426c0f734f38f6"
   strings:
      $x1 = "B4490-2314-55C1- /Processid:{321bitsadmin /canceft\\windows\\curresoftware\\microso" fullword ascii
      $x2 = "D:\\Work\\VS\\House\\TSSL\\TSSL\\TClient" ascii
      $x3 = "\\Release\\FakeRun.pdb" ascii
      $x4 = "FakeRun.dll" fullword ascii

      $s1 = "cmd.exe /c \"%s\"" fullword ascii
      $s2 = "CreateProcess failed (%d)" fullword ascii
      $s3 = "CreateProcess %s " fullword ascii
      $s4 = "FindResource %s error " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) or 4 of them )
}

rule KeyBoy_rasauto {
   meta:
      description = "Detects KeyBoy ServiceClient"
      author = "Markus Neis, Florian Roth"
      reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/tropic-trooper-new-strategy/"
      date = "2018-03-26"
      hash1 = "49df4fec76a0ffaee5e4d933a734126c1a7b32d1c9cb5ab22a868e8bfc653245"
   strings:
      $x1 = "rundll32.exe %s SSSS & exit" fullword ascii
      $x2 = "D:\\Work\\Project\\VS\\HSSL\\HSSL_Unicode _2\\Release\\ServiceClient.pdb" fullword ascii

      $s1 = "cmd.exe /c \"%s\"" fullword ascii
      $s2 = "CreateProcess failed (%d)" fullword ascii
      $s3 = "ServiceClient.dll" fullword ascii
      $s4 = "NtWow64QueryInformationProcess64 failed" fullword ascii
      $s5 = "pid:%d CmdLine:%S" fullword ascii
      $s6 = "rasauto32.ServiceMain" fullword ascii
      $s7 = "del /q/f %s\\%s*" fullword ascii
      $s8 = "szTmpDll:%s" fullword ascii
      $s9 = "lpCmdLine:%s" fullword ascii
      $s0 = "ReleaseFileFromRes:%s ok!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         pe.exports("SSSS") or
         1 of ($x*) or
         4 of them
      )
}

rule KeyBoy_876_0x4e20000 {
   meta:
      description = "Detects KeyBoy Backdoor"
      author = "Markus Neis, Florian Roth"
      reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/tropic-trooper-new-strategy/"
      date = "2018-03-26"
      hash1 = "6e900e5b6dc4f21a004c5b5908c81f055db0d7026b3c5e105708586f85d3e334"
   strings:
      $x1 = "%s\\rundll32.exe %s ServiceTake %s %s" fullword ascii
      $x2 = "#%sCmd shell is not running,or your cmd is error!" fullword ascii
      $x3 = "Take Screen Error,May no user login!" fullword ascii
      $x4 = "Get logon user fail!" fullword ascii
      $x5 = "8. LoginPasswd:%s" fullword ascii
      $x6 = "Take Screen Error,service dll not exists" fullword ascii

      $s1 = "taskkill /f /pid %s" fullword ascii
      $s2 = "TClient.exe" fullword ascii
      $s3 = "%s\\wab32res.dll" fullword ascii
      $s4 = "%s\\rasauto.dll" fullword ascii
      $s5 = "Download file:%s index:%d" fullword ascii
      $s6 = "LogonUser: [%s]" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and (
        1 of ($x*) or
        3 of them
      )
}
