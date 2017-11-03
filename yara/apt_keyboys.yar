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
